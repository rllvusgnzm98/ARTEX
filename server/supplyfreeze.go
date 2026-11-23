package server

import (
	"errors"
	"sync"

	"github.com/Autumn-27/artex/agent"
)

// supplyHolds is the in-process freeze latch for a task whose provider has
// failed (403/402/quota or an exhausted failover chain). A task with a
// persisted LLMFailoverState of "chain_exhausted" is frozen even after a
// restart; this map covers the no-explicit-chain path (global / single
// profile) until an operator resets health or edits the chain.
var supplyHolds sync.Map // taskID -> struct{}

// supplyMu orders a revision-checked hold against the release a chain
// replacement issues after publishing its new revision.
var supplyMu sync.Mutex

func holdTaskSupply(taskID string) {
	if taskID == "" {
		return
	}
	supplyMu.Lock()
	defer supplyMu.Unlock()
	supplyHolds.Store(taskID, struct{}{})
}

func releaseTaskSupply(taskID string) {
	if taskID == "" {
		return
	}
	supplyMu.Lock()
	defer supplyMu.Unlock()
	supplyHolds.Delete(taskID)
}

func releaseAllTaskSupply() {
	supplyMu.Lock()
	defer supplyMu.Unlock()
	supplyHolds.Range(func(key, _ any) bool {
		supplyHolds.Delete(key)
		return true
	})
}

func memorySupplyHeld(taskID string) bool {
	_, ok := supplyHolds.Load(taskID)
	return ok
}

// taskSupplyFrozen reports whether workers and the planner must stand down:
// no new claims, no empty re-dispatch, no settling the task as done.
func taskSupplyFrozen(t *Task) bool {
	if t == nil {
		return false
	}
	if t.llmStateSnapshot().FailoverState == "chain_exhausted" {
		return true
	}
	return memorySupplyHeld(t.ID)
}

// applySupplyHold freezes dispatch for the task. The already-written session,
// graph, and progress are left alone; the caller parks the intent separately.
func applySupplyHold(t *Task) {
	if t == nil {
		return
	}
	holdTaskSupply(t.ID)
}

// applySupplyHoldAt freezes dispatch for a supply failure observed at chain
// revision (0 = unknown). A chain replaced since then already released the
// hold, so a late failure must not restore it. Replacement publishes the new
// revision before releaseTaskSupply, so checking under supplyMu is enough.
func applySupplyHoldAt(t *Task, revision int64) bool {
	if t == nil || t.ID == "" {
		return false
	}
	supplyMu.Lock()
	defer supplyMu.Unlock()
	if revision > 0 && t.llmStateSnapshot().ChainRevision > revision {
		return false
	}
	supplyHolds.Store(t.ID, struct{}{})
	return true
}

func taskLLMErrorRevision(err error) int64 {
	var target *taskLLMError
	if errors.As(err, &target) {
		return target.revision
	}
	return 0
}

// shouldClaimWork is the engine-side dispatch gate.
func shouldClaimWork(t *Task) bool {
	return agent.ShouldDispatch(taskSupplyFrozen(t))
}
