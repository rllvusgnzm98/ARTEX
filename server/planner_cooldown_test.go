package server

import (
	"context"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/llm"
)

func TestPlannerCooldownCoalescesDoneAndBypassesUrgentOrStarved(t *testing.T) {
	t.Setenv("ARTEX_SKILL_DIR", t.TempDir())
	pg := openTestPG(t)
	m := &Manager{pg: pg, dir: t.TempDir(), tasks: map[string]*Task{}}
	row, err := pg.CreateTask("cooldown-test", "verify tiered cooldown", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM plan_rounds WHERE task_id=$1`, strconv.FormatInt(row.ID, 10))
		_ = pg.DeleteTask(row.ID)
	})
	store := pg.Exploration(row.ExplorationID)
	if _, err := store.AddGoal(map[string]any{"summary": "open goal"}, "test"); err != nil {
		t.Fatal(err)
	}
	// Seed one open intent so frontier is NOT starved during cooldown.
	openID, err := store.AddIntent(map[string]any{"summary": "queued work"}, 0, nil, "test")
	if err != nil {
		t.Fatal(err)
	}

	task := &Task{
		ID:     strconv.FormatInt(row.ID, 10),
		ExpID:  row.ExplorationID,
		Goal:   "verify tiered cooldown",
		Status: "running",
		Store:  store,
		notify: make(chan struct{}, 1),
	}
	m.tasks[task.ID] = task

	var planCount atomic.Int32
	roundDone := make(chan int32, 10)
	prov := retestProvider{complete: func(ctx context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		n := planCount.Add(1)
		select {
		case roundDone <- n:
		default:
		}
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("ok")}}, "end_turn", llm.Usage{}, nil
	}}
	pl := agent.NewPlanner(prov, "test", m.dir, nil, 0, 1)
	pl.SetNonStreaming(func() bool { return true })

	e := NewEngine(m)
	e.debounce = 20 * time.Millisecond
	e.SetPlanCooldown(350 * time.Millisecond)
	e.SetAuthoritativeAgentResolver(func(*Task) (*agent.Planner, *agent.Worker) { return pl, nil })

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	doneLoop := make(chan struct{})
	go func() {
		defer close(doneLoop)
		e.plannerLoop(ctx, task)
	}()
	t.Cleanup(func() {
		cancel()
		<-doneLoop
	})

	// Round 1: initial wake runs immediately (lastPlanAt is zero).
	task.Notify()
	select {
	case <-roundDone:
	case <-time.After(3 * time.Second):
		t.Fatal("round 1 did not run")
	}

	// Burst two routine NotifyDone events while open > 0: must wait out cooldown and coalesce into 1 round.
	beforeBurst := time.Now()
	task.NotifyDone(101)
	time.Sleep(50 * time.Millisecond)
	task.NotifyDone(102)
	select {
	case n := <-roundDone:
		elapsed := time.Since(beforeBurst)
		if n != 2 {
			t.Fatalf("expected round 2, got %d", n)
		}
		if elapsed < 280*time.Millisecond {
			t.Fatalf("routine NotifyDone burst bypassed cooldown too early: elapsed=%s", elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("coalesced round 2 did not run after cooldown")
	}

	// Give a brief window to confirm the two NotifyDone events coalesced into ONE round, not two.
	time.Sleep(100 * time.Millisecond)
	if got := planCount.Load(); got != 2 {
		t.Fatalf("NotifyDone burst triggered %d rounds total, want 2 (coalesced)", got)
	}

	// Urgent wake (NotifyFinding) must bypass cooldown immediately!
	e.SetPlanCooldown(5 * time.Second)
	urgentStart := time.Now()
	task.NotifyFinding(101, "RCE confirmed")
	select {
	case n := <-roundDone:
		if n != 3 {
			t.Fatalf("expected round 3, got %d", n)
		}
		if elapsed := time.Since(urgentStart); elapsed > time.Second {
			t.Fatalf("urgent NotifyFinding was delayed by cooldown: %s", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("urgent NotifyFinding did not bypass cooldown")
	}

	// Frontier starvation (open == 0) must ALSO bypass cooldown immediately!
	if err := store.SetIntentState(openID, "done"); err != nil {
		t.Fatal(err)
	}
	starveStart := time.Now()
	task.NotifyDone(openID)
	select {
	case n := <-roundDone:
		if n != 4 {
			t.Fatalf("expected round 4, got %d", n)
		}
		if elapsed := time.Since(starveStart); elapsed > time.Second {
			t.Fatalf("starved-frontier NotifyDone was delayed by cooldown: %s", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("starved-frontier NotifyDone did not bypass cooldown")
	}
}

func TestTaskActiveLLMProfileIDAndForgetTaskHealth(t *testing.T) {
	pg := openTestPG(t)
	m := &Manager{pg: pg, tasks: map[string]*Task{}}
	p1, p2 := int64(11), int64(22)
	task := &Task{ID: "77", ExpID: 909, LLMProfileID: &p1, ActiveLLMProfileID: &p2}
	m.tasks[task.ID] = task
	s := &Server{m: m}

	if got := s.taskActiveLLMProfileID("77"); got == nil || *got != 22 {
		t.Fatalf("taskActiveLLMProfileID with ActiveID = %v, want 22", got)
	}
	task.setLLMState(&p1, nil, nil, 1, "", "")
	if got := s.taskActiveLLMProfileID("77"); got == nil || *got != 11 {
		t.Fatalf("taskActiveLLMProfileID with ProfileID fallback = %v, want 11", got)
	}
	task.setLLMState(nil, nil, nil, 2, "", "")
	if got := s.taskActiveLLMProfileID("77"); got != nil {
		t.Fatalf("taskActiveLLMProfileID with no task profile = %v, want nil", *got)
	}

	// Verify intercept.TaskIDFromContext round-trip.
	ctx := intercept.WithTaskContext(t.Context(), "77", "worker", nil)
	if got := intercept.TaskIDFromContext(ctx); got != "77" {
		t.Fatalf("TaskIDFromContext = %q, want 77", got)
	}

	// Verify forgetTask releases PersistenceHealth for the removed exploration.
	pg.Health().RecordWriteFailure(909, "synthetic write failure")
	if pg.Health().Snapshot(909).Healthy() {
		t.Fatal("expected unhealthy before forgetTask")
	}
	m.forgetTask("77", 77)
	if !pg.Health().Snapshot(909).Healthy() {
		t.Fatal("forgetTask must release PersistenceHealth state for removed task")
	}
}
