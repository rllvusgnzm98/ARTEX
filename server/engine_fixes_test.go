package server

import (
	"errors"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/harness"
)

func TestPlannerEffectiveCooldown(t *testing.T) {
	base := 20 * time.Second
	if got := plannerEffectiveCooldown(base, 0); got != 20*time.Second {
		t.Fatalf("streak=0: got %v, want 20s", got)
	}
	if got := plannerEffectiveCooldown(base, 1); got != 20*time.Second {
		t.Fatalf("streak=1: got %v, want 20s", got)
	}
	if got := plannerEffectiveCooldown(base, 2); got != 40*time.Second {
		t.Fatalf("streak=2: got %v, want 40s", got)
	}
	if got := plannerEffectiveCooldown(base, 3); got != 80*time.Second {
		t.Fatalf("streak=3: got %v, want 80s", got)
	}
	if got := plannerEffectiveCooldown(base, 4); got != 160*time.Second {
		t.Fatalf("streak=4: got %v, want 160s", got)
	}
	if got := plannerEffectiveCooldown(base, 5); got != maxPlannerBackoffCooldown {
		t.Fatalf("streak=5: got %v, want cap %v", got, maxPlannerBackoffCooldown)
	}
	if got := plannerEffectiveCooldown(base, 20); got != maxPlannerBackoffCooldown {
		t.Fatalf("streak=20: got %v, want cap %v", got, maxPlannerBackoffCooldown)
	}
}

func TestShouldSkipHeartbeatPlan(t *testing.T) {
	pg := openIntranetTestDB(t)
	row, err := pg.CreateTask("heartbeat skip test", "verify deterministic precheck", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(row.ID) })

	es := pg.Exploration(row.ExplorationID)
	runningID, err := es.AddIntent(map[string]any{"summary": "active work"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := es.ClaimIntent(runningID, "w1"); err != nil || !ok {
		t.Fatalf("ClaimIntent: ok=%v err=%v", ok, err)
	}

	e := NewEngine(nil)
	task := &Task{ID: "1", ExpID: row.ExplorationID, Store: es}
	now := time.Now()
	interval := 60 * time.Second

	// No recent activity yet -> must not skip.
	if skip, _ := e.shouldSkipHeartbeatPlan(task, interval, db.StalledIntentStamp{}, now); skip {
		t.Fatal("no recent activity must not skip heartbeat")
	}

	// Recent activity + running intent + no urgent wake + no stalled intents -> skip!
	e.touch(task.ID)
	skip, st := e.shouldSkipHeartbeatPlan(task, interval, db.StalledIntentStamp{}, now)
	if !skip {
		t.Fatal("active running worker with recent activity should skip heartbeat LLM")
	}

	// Urgent wake pending -> must not skip.
	task.NotifyFinding(runningID, "new finding")
	if skipUrgent, _ := e.shouldSkipHeartbeatPlan(task, interval, st, now); skipUrgent {
		t.Fatal("urgent wake must bypass heartbeat skip")
	}
	task.drainTriggers()

	// Stale activity (>= interval) -> must not skip.
	if skipStale, _ := e.shouldSkipHeartbeatPlan(task, interval, st, now.Add(interval+time.Second)); skipStale {
		t.Fatal("stale activity beyond interval must not skip heartbeat")
	}

	// Newly blocked/exhausted intent -> must not skip.
	blockedID, err := es.AddIntent(map[string]any{"summary": "blocked work"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := es.SetIntentState(blockedID, "blocked"); err != nil {
		t.Fatal(err)
	}
	if skipBlocked, newSt := e.shouldSkipHeartbeatPlan(task, interval, st, now); skipBlocked || newSt.Count != 1 {
		t.Fatalf("newly blocked intent must not skip heartbeat: skip=%v st=%+v", skipBlocked, newSt)
	}
}

func TestSettlementTransientErrorRouting(t *testing.T) {
	t.Parallel()
	ste := &agent.SettlementTransientError{
		BudgetErr:   errors.New("budget deadline"),
		RecoveryErr: errors.New("status 503 service unavailable"),
	}
	if retryableWorkerModelError(harness.ReasonModelError, ste) {
		t.Fatal("SettlementTransientError must not trigger full worker replay in runIntent")
	}
	cls, sig := workerTerminationOutcome(harness.ReasonTimeout, ste, agent.WriteCounts{}, nil)
	if cls != "settlement_transient" || sig != "settlement_llm_outage" {
		t.Fatalf("workerTerminationOutcome = (%q, %q), want (settlement_transient, settlement_llm_outage)", cls, sig)
	}
}
