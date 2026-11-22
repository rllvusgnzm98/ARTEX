package server

import (
	"context"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/google/uuid"
)

func TestPlanIntentDelta(t *testing.T) {
	for _, tc := range []struct {
		name             string
		before, after    map[string]int
		added, cancelled int
	}{
		{"empty", map[string]int{}, map[string]int{}, 0, 0},
		{"added and stopped", map[string]int{"open": 2}, map[string]int{"open": 3, "stopped": 1}, 2, 1},
		{"completed", map[string]int{"running": 2}, map[string]int{"done": 1, "exhausted": 1}, 0, 0},
		{"clamp negative", map[string]int{"stopped": 3, "open": 2}, map[string]int{"stopped": 1}, 0, 0},
		{"failed before query", nil, map[string]int{"open": 2}, 0, 0},
		{"failed after query", map[string]int{"open": 2}, nil, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			added, cancelled := planIntentDelta(tc.before, tc.after)
			if added != tc.added || cancelled != tc.cancelled {
				t.Fatalf("delta=(%d,%d) want (%d,%d)", added, cancelled, tc.added, tc.cancelled)
			}
		})
	}
}

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
		_, _ = pg.Exec(`DELETE FROM plan_rounds WHERE task_id=$1`, task.ID)
		_, _ = pg.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	})
	e := NewEngine(&Manager{pg: pg})
	e.restorePlanRoundCounter(t.Context(), task)
	if got := e.nextPlannerRound(task.ID); got != 1 {
		t.Fatalf("first round=%d", got)
	}
	before := planIntentCounts(t.Context(), task)
	if _, err := task.Store.AddNode("intent", map[string]any{"summary": "test"}, 1, "stopped", "planner", nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // A cancelled planning run must still be observable.
	e.recordPlanRound(ctx, task, db.PlanRound{TaskID: task.ID, Round: 1, StartedAt: time.Now(),
		Outcome: "error", LLMCalls: 3}, before)
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
	// Duplicate-write failure is best effort and must not panic or replace a row.
	e.recordPlanRound(t.Context(), task, db.PlanRound{TaskID: task.ID, Round: 1, StartedAt: time.Now(), Outcome: "ok"}, before)
	var outcome string
	if err := pg.QueryRow(`SELECT outcome FROM plan_rounds WHERE task_id=$1 AND round=1`, task.ID).Scan(&outcome); err != nil || outcome != "error" {
		t.Fatalf("duplicate write changed outcome=%q err=%v", outcome, err)
	}
}
