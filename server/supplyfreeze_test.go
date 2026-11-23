package server

import (
	"errors"
	"fmt"
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
