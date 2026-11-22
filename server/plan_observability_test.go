package server

import (
	"context"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/llmrec"
	"github.com/google/uuid"
)

func TestRecordPlanRoundAndRestoreCounter(t *testing.T) {
	pg := openTestPG(t)
	if err := pg.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	expID, err := pg.CreateExploration("plan-record", "goal")
	if err != nil {
		t.Fatal(err)
	}
	task := &Task{ID: "plan-record-" + uuid.NewString(), Store: pg.Exploration(expID)}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM llm_usage WHERE task_id=$1`, task.ID)
		_, _ = pg.Exec(`DELETE FROM plan_rounds WHERE task_id=$1`, task.ID)
		_, _ = pg.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	})
	e := NewEngine(&Manager{pg: pg})
	e.restorePlanRoundCounter(t.Context(), task)
	if got := e.nextPlannerRound(task.ID); got != 1 {
		t.Fatalf("first round=%d", got)
	}
	if _, err := task.Store.AddNode("intent", map[string]any{"summary": "test"}, 1, "stopped", "planner", nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	ctx = llmrec.WithAttribution(ctx, 0, "planner", 1)
	llmrec.RecordIntentCreated(ctx)
	cancel() // A cancelled planning run must still be observable.
	e.recordPlanRound(ctx, task, db.PlanRound{TaskID: task.ID, Round: 1, StartedAt: time.Now(),
		Outcome: "error", LLMCalls: 3})
	llmrec.RecordIntentCancelled(ctx) // Completion after Plan returned updates the same round.
	var added, stopped, calls int
	if err := pg.QueryRow(`SELECT intents_added,intents_cancelled,llm_calls FROM plan_rounds WHERE task_id=$1 AND round=1`, task.ID).
		Scan(&added, &stopped, &calls); err != nil || added != 1 || stopped != 1 || calls != 3 {
		t.Fatalf("record=%d/%d/%d err=%v", added, stopped, calls, err)
	}
	restarted := NewEngine(&Manager{pg: pg})
	restarted.restorePlanRoundCounter(t.Context(), task)
	if got := restarted.nextPlannerRound(task.ID); got != 2 {
		t.Fatalf("restarted round=%d want 2", got)
	}
	if err := pg.InsertLLMUsage(&db.LLMUsage{TaskID: task.ID, Worker: "planner", PlanRound: 7}); err != nil {
		t.Fatal(err)
	}
	interrupted := NewEngine(&Manager{pg: pg})
	interrupted.restorePlanRoundCounter(t.Context(), task)
	if got := interrupted.nextPlannerRound(task.ID); got != 8 {
		t.Fatalf("interrupted restart round=%d want 8", got)
	}
	// Duplicate-write failure is best effort and must not panic or replace a row.
	e.recordPlanRound(t.Context(), task, db.PlanRound{TaskID: task.ID, Round: 1, StartedAt: time.Now(), Outcome: "ok"})
	var outcome string
	if err := pg.QueryRow(`SELECT outcome FROM plan_rounds WHERE task_id=$1 AND round=1`, task.ID).Scan(&outcome); err != nil || outcome != "error" {
		t.Fatalf("duplicate write changed outcome=%q err=%v", outcome, err)
	}
}
