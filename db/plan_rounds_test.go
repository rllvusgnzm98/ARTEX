package db

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPlanObservabilitySchemaAndPersistence(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	for range 2 {
		if err := d.EnsureLLMUsageTable(); err != nil {
			t.Fatal(err)
		}
	}
	var indexed bool
	if err := d.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename='llm_usage'
AND indexname='idx_llm_usage_task_intent' AND indexdef LIKE '%(task_id, intent_id)%')`).Scan(&indexed); err != nil || !indexed {
		t.Fatalf("task/intent index exists=%v err=%v", indexed, err)
	}
	taskID := "plan-observability-" + uuid.NewString()
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM llm_usage WHERE task_id=$1`, taskID)
		_, _ = d.Exec(`DELETE FROM plan_rounds WHERE task_id=$1`, taskID)
	})
	u := &LLMUsage{TaskID: taskID, IntentID: 4294967296, WorkerInstance: "work#2", PlanRound: 4, Status: "ok"}
	if got, err := d.LatestPlanRound(t.Context(), taskID); err != nil || got != 0 {
		t.Fatalf("empty latest=%d err=%v", got, err)
	}
	if err := d.InsertLLMUsage(u); err != nil {
		t.Fatal(err)
	}
	var intentID, round int64
	var instance string
	if err := d.QueryRow(`SELECT intent_id,worker_instance,plan_round FROM llm_usage WHERE task_id=$1`, taskID).
		Scan(&intentID, &instance, &round); err != nil {
		t.Fatal(err)
	}
	if intentID != u.IntentID || instance != u.WorkerInstance || round != u.PlanRound {
		t.Fatalf("usage attribution=(%d,%q,%d)", intentID, instance, round)
	}
	if err := d.InsertLLMUsage(&LLMUsage{TaskID: taskID, Status: "error"}); err != nil {
		t.Fatal(err)
	}
	var empty int
	if err := d.QueryRow(`SELECT count(*) FROM llm_usage WHERE task_id=$1 AND intent_id IS NULL
AND worker_instance IS NULL AND plan_round IS NULL`, taskID).Scan(&empty); err != nil || empty != 1 {
		t.Fatalf("unattributed rows=%d err=%v", empty, err)
	}
	if got, err := d.LatestPlanRound(t.Context(), taskID); err != nil || got != 4 {
		t.Fatalf("usage-only latest=%d err=%v", got, err)
	}
	for i, outcome := range []string{"ok", "error", "met"} {
		want := PlanRound{TaskID: taskID, Round: int64(i + 1), StartedAt: time.Now().UTC().Truncate(time.Microsecond),
			DurationMS: 321, TriggerSrc: "edge", TriggerCount: 2, LLMCalls: 5, IntentsAdded: 3, IntentsCancelled: 1, Outcome: outcome}
		if err := d.InsertPlanRound(t.Context(), want); err != nil {
			t.Fatal(err)
		}
		var got PlanRound
		if err := d.QueryRow(`SELECT task_id,round,started_at,duration_ms,trigger_src,trigger_count,llm_calls,
intents_added,intents_cancelled,outcome FROM plan_rounds WHERE task_id=$1 AND round=$2`, taskID, want.Round).
			Scan(&got.TaskID, &got.Round, &got.StartedAt, &got.DurationMS, &got.TriggerSrc, &got.TriggerCount,
				&got.LLMCalls, &got.IntentsAdded, &got.IntentsCancelled, &got.Outcome); err != nil {
			t.Fatal(err)
		}
		got.StartedAt = got.StartedAt.UTC()
		if got != want {
			t.Fatalf("plan round=%+v want %+v", got, want)
		}
		if err := d.InsertPlanRound(t.Context(), want); err == nil {
			t.Fatal("duplicate primary key accepted")
		}
	}
	if got, err := d.LatestPlanRound(t.Context(), taskID); err != nil || got != 4 {
		t.Fatalf("latest=%d err=%v", got, err)
	}
	if err := d.InsertPlanRound(t.Context(), PlanRound{TaskID: taskID, Round: 4, StartedAt: time.Now(), Outcome: "invalid"}); err == nil {
		t.Fatal("invalid outcome accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := d.InsertPlanRound(ctx, PlanRound{TaskID: taskID, Round: 4}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled insert error=%v", err)
	}
}

func TestIntentCountsByState(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	expID, err := d.CreateExploration("plan-counts", "goal")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) })
	store := d.Exploration(expID)
	counts, err := store.IntentCountsByState(t.Context())
	if err != nil || len(counts) != 0 {
		t.Fatalf("empty counts=%v err=%v", counts, err)
	}
	if _, err := store.AddGoal(map[string]any{"text": "goal"}, "human"); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"open", "open", "stopped", "done"} {
		if _, err := store.AddNode("intent", map[string]any{"summary": "test"}, 1, state, "planner", nil); err != nil {
			t.Fatal(err)
		}
	}
	counts, err = store.IntentCountsByState(t.Context())
	if err != nil || len(counts) != 3 || counts["open"] != 2 || counts["stopped"] != 1 || counts["done"] != 1 {
		t.Fatalf("counts=%v err=%v", counts, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := store.IntentCountsByState(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled counts error=%v", err)
	}
}
