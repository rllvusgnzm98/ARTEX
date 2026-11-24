package server

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/norma/harness"
)

func TestTaskSupplyFrozenFromChainStateAndHold(t *testing.T) {
	t.Cleanup(releaseAllTaskSupply)

	if taskSupplyFrozen(nil) {
		t.Fatal("nil task is not frozen")
	}

	plain := &Task{ID: "task-plain"}
	if taskSupplyFrozen(plain) || !shouldClaimWork(plain) {
		t.Fatal("a healthy task must remain dispatchable")
	}

	holdTaskSupply("task-held")
	held := &Task{ID: "task-held"}
	if !taskSupplyFrozen(held) || shouldClaimWork(held) {
		t.Fatal("memory hold must freeze dispatch")
	}
	releaseTaskSupply("task-held")
	if taskSupplyFrozen(held) {
		t.Fatal("release must clear the memory hold")
	}

	exhausted := &Task{ID: "task-chain"}
	exhausted.setLLMState(nil, nil, []int64{7}, 1, "chain_exhausted", "status 402")
	if !taskSupplyFrozen(exhausted) || shouldClaimWork(exhausted) {
		t.Fatal("persisted chain_exhausted must freeze dispatch without a memory hold")
	}
}

func TestFrozenTaskDoesNotIdleRedispatch(t *testing.T) {
	t.Cleanup(releaseAllTaskSupply)
	task := &Task{ID: "task-spin"}
	holdTaskSupply(task.ID)

	claims := 0
	for i := 0; i < 10; i++ {
		if shouldClaimWork(task) {
			claims++
		}
	}
	if claims != 0 {
		t.Fatalf("claims=%d, want 0 empty re-dispatch while supply-failed", claims)
	}
}

func TestSupplyFreezeDoesNotSettleTaskAsDone(t *testing.T) {
	t.Cleanup(releaseAllTaskSupply)
	task := &Task{ID: "task-scene"}
	// Simulate a live task that already has graph/session progress.
	applySupplyHold(task)
	settle := agent.SettleWorkerRun(harness.ReasonModelError, errors.New("status 403: forbidden"))
	if settle.TaskStatus != "" || settle.IntentState == "done" || settle.IntentState == "blocked" {
		t.Fatalf("supply interrupt must not settle success/blocked, got %+v", settle)
	}
	if !taskSupplyFrozen(task) {
		t.Fatal("scene freeze was not held")
	}
	if !settle.FreezeScene || settle.TargetFailureWrites != 0 {
		t.Fatalf("expected freeze with zero target-failure writes, got %+v", settle)
	}
}

func TestOptionalFailoverStillClassifiesWithoutSecondModel(t *testing.T) {
	// The existing llmpool path remains the failover mechanism. A single
	// provider (no mandatory second model / profile archive) is enough to
	// freeze once that provider surfaces a supply error.
	settle := agent.SettleWorkerRun(harness.ReasonCompleted, nil)
	supply := agent.SettleWorkerRun(harness.ReasonModelError, errors.New("status 402: payment required"))
	if settle.TerminalKind == supply.TerminalKind {
		t.Fatal("optional single-provider freeze must not reuse the empty-completion terminal")
	}
	if !supply.FreezeScene || !supply.SupplyFailure {
		t.Fatalf("single provider 402 should freeze, got %+v", supply)
	}
}

func TestTaskLLMChainExhaustedIsSupplyFailure(t *testing.T) {
	exhausted := &taskLLMError{taskID: "1", chainExhausted: true, cause: errors.New("status 402: payment required")}
	if !errors.Is(exhausted, agent.ErrProviderChainExhausted) {
		t.Fatal("chain-exhausted router error must match ErrProviderChainExhausted")
	}
	if !agent.IsSupplyFailure(exhausted) {
		t.Fatal("chain-exhausted router error must classify as a supply failure")
	}
	s := agent.SettleWorkerRun(harness.ReasonModelError, exhausted)
	if !s.FreezeScene || s.IntentState == "blocked" || s.IntentState == "done" || s.TargetFailureWrites != 0 {
		t.Fatalf("chain exhaustion must freeze without blocked/done, got %+v", s)
	}

	partial := &taskLLMError{taskID: "1", cause: errors.New("status 402: payment required")}
	if errors.Is(partial, agent.ErrProviderChainExhausted) {
		t.Fatal("a non-exhausted router error must not match the chain-exhausted sentinel")
	}
	// A 402 that has not exhausted the chain is still a supply failure (single
	// provider / no remaining failover), but via the status, not the sentinel.
	if !agent.IsSupplyFailure(partial) {
		t.Fatal("402 cause should still classify as supply failure")
	}

	wrapped := fmt.Errorf("worker: %w", exhausted)
	if !errors.Is(wrapped, agent.ErrProviderChainExhausted) || !agent.IsSupplyFailure(wrapped) {
		t.Fatal("wrapped chain-exhausted error must still classify")
	}
}

func TestLateSupplyFailureDoesNotRefreezeReplacedChain(t *testing.T) {
	t.Cleanup(releaseAllTaskSupply)
	task := &Task{ID: "task-replaced", LLMChainRevision: 5}
	if applySupplyHoldAt(task, 4) || taskSupplyFrozen(task) {
		t.Fatal("failure from a replaced chain revision must not freeze the task")
	}
	if !applySupplyHoldAt(task, 5) || !taskSupplyFrozen(task) {
		t.Fatal("failure at the current revision must freeze the task")
	}
	releaseTaskSupply(task.ID)
	if !applySupplyHoldAt(task, 0) || !taskSupplyFrozen(task) {
		t.Fatal("failure with unknown revision keeps the legacy freeze")
	}
}

func TestStaleSupplyFailuresAfterReplacementLeaveTaskUnfrozen(t *testing.T) {
	t.Cleanup(releaseAllTaskSupply)
	for round := 0; round < 200; round++ {
		task := &Task{ID: "task-race", LLMChainRevision: 4}
		var wg sync.WaitGroup
		replaced := make(chan struct{})
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				applySupplyHoldAt(task, 4)
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			task.llmMu.Lock()
			task.LLMChainRevision = 5
			task.llmMu.Unlock()
			releaseTaskSupply(task.ID)
			close(replaced)
		}()
		<-replaced
		wg.Wait()
		// Every stale hold either preceded the release or saw revision 5.
		if taskSupplyFrozen(task) {
			t.Fatalf("round %d: stale failure refroze the replaced chain", round)
		}
		if !applySupplyHoldAt(task, 5) || !taskSupplyFrozen(task) {
			t.Fatalf("round %d: current-revision failure did not freeze", round)
		}
		releaseTaskSupply(task.ID)
	}
}

func TestReleaseAllTaskSupplyConcurrentWithHold(t *testing.T) {
	t.Cleanup(releaseAllTaskSupply)
	task := &Task{ID: "task-release-all", LLMChainRevision: 2}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				applySupplyHoldAt(task, 2)
				_ = taskSupplyFrozen(task)
				releaseAllTaskSupply()
			}
		}()
	}
	wg.Wait()
	releaseAllTaskSupply()
	if taskSupplyFrozen(task) {
		t.Fatal("task should be unfrozen after releaseAllTaskSupply")
	}
}

func TestAdmitPausedTaskReleasesMemorySupplyHoldButRespectsChainExhausted(t *testing.T) {
	t.Cleanup(releaseAllTaskSupply)
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()
	defer restoreConcurrencySetting(t, m)()
	if err := m.SetConcurrency(false, 0); err != nil {
		t.Fatal(err)
	}

	task, err := m.CreateTask("resume-unfreeze", "verify resume clears memory hold", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()

	s := newAdmissionTestServer(m, nil)
	if err := m.ApplyTaskPause(task.ID); err != nil {
		t.Fatal(err)
	}
	holdTaskSupply(task.ID)
	if !taskSupplyFrozen(task) {
		t.Fatal("expected memory supply hold before resume")
	}
	if _, err := s.admitPausedTask(task); err != nil {
		t.Fatalf("admitPausedTask failed: %v", err)
	}
	if taskSupplyFrozen(task) {
		t.Fatal("admitPausedTask must clear in-memory supplyHolds for single/global profile")
	}

	// Persisted chain_exhausted remains frozen until the chain itself is replaced.
	task2, err := m.CreateTask("resume-chain-exhausted", "verify chain_exhausted stays frozen", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.DeleteTask(task2.ID, DeleteTaskOptions{}) }()
	if err := m.ApplyTaskPause(task2.ID); err != nil {
		t.Fatal(err)
	}
	holdTaskSupply(task2.ID)
	task2.setLLMState(nil, nil, []int64{7}, 1, "chain_exhausted", "status 402")
	if _, err := s.admitPausedTask(task2); err != nil {
		t.Fatalf("admitPausedTask(chain_exhausted) failed: %v", err)
	}
	if memorySupplyHeld(task2.ID) {
		t.Fatal("memory hold should still be cleared on resume")
	}
	if !taskSupplyFrozen(task2) {
		t.Fatal("persisted chain_exhausted must keep task frozen across resume")
	}
}

