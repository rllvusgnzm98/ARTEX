package db

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPlanRoundsDeletedTransactionally(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	guard := "plan_round_delete_guard_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := d.Exec(`CREATE TABLE ` + guard + ` (task_id BIGINT REFERENCES tasks(id))`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DROP TABLE ` + guard) })
	for _, archived := range []bool{false, true} {
		t.Run(fmt.Sprintf("archived=%t", archived), func(t *testing.T) {
			task, err := d.CreateTask("round deletion", "goal", nil, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			taskID := fmt.Sprint(task.ID)
			t.Cleanup(func() {
				_, _ = d.Exec(`DELETE FROM `+guard+` WHERE task_id=$1`, task.ID)
				_, _ = d.Exec(`DELETE FROM task_archives WHERE task_id=$1`, task.ID)
				_, _ = d.Exec(`DELETE FROM llm_usage WHERE task_id=$1`, taskID)
				_ = d.DeleteTask(task.ID)
			})
			if err := d.InsertPlanRound(t.Context(), PlanRound{TaskID: taskID, Round: 1, StartedAt: time.Now(), Outcome: "ok"}); err != nil {
				t.Fatal(err)
			}
			if err := d.InsertLLMUsage(&LLMUsage{TaskID: taskID, Worker: "planner", PlanRound: 1}); err != nil {
				t.Fatal(err)
			}
			remove := func() error { return d.DeleteTask(task.ID) }
			if archived {
				if _, err := d.Exec(`UPDATE tasks SET archived_at=now() WHERE id=$1`, task.ID); err != nil {
					t.Fatal(err)
				}
				var archiveID int64
				if err := d.QueryRow(`INSERT INTO task_archives(task_id,state) VALUES($1,'deleting') RETURNING id`, task.ID).Scan(&archiveID); err != nil {
					t.Fatal(err)
				}
				remove = func() error { return d.DeleteTaskArchiveStub(archiveID) }
			}
			if _, err := d.Exec(`INSERT INTO `+guard+` VALUES($1)`, task.ID); err != nil {
				t.Fatal(err)
			}
			if err := remove(); err == nil {
				t.Fatal("expected restricted task deletion to fail")
			}
			var rounds int
			if err := d.QueryRow(`SELECT count(*) FROM plan_rounds WHERE task_id=$1`, taskID).Scan(&rounds); err != nil || rounds != 1 {
				t.Fatalf("rollback rounds=%d err=%v", rounds, err)
			}
			if _, err := d.Exec(`DELETE FROM `+guard+` WHERE task_id=$1`, task.ID); err != nil {
				t.Fatal(err)
			}
			if err := remove(); err != nil {
				t.Fatal(err)
			}
			if err := d.QueryRow(`SELECT count(*) FROM plan_rounds WHERE task_id=$1`, taskID).Scan(&rounds); err != nil || rounds != 0 {
				t.Fatalf("remaining rounds=%d err=%v", rounds, err)
			}
			var usage int
			if err := d.QueryRow(`SELECT count(*) FROM llm_usage WHERE task_id=$1`, taskID).Scan(&usage); err != nil || usage != 1 {
				t.Fatalf("historical usage=%d err=%v", usage, err)
			}
			if err := remove(); err != nil && !archived {
				t.Fatalf("idempotent deletion: %v", err)
			}
		})
	}
}
