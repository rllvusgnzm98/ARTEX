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
var supplyHolds sync.Map // taskID -> *supplyHold

// supplyHold is a distinct token per hold, so a rollback removes only its own.
// revision is the chain revision it was set for (0 = unknown).
type supplyHold struct{ revision int64 }

func holdTaskSupply(taskID string) {
	if taskID == "" {
		return
	}
	supplyHolds.Store(taskID, &supplyHold{})
}

func releaseTaskSupply(taskID string) {
	if taskID == "" {
		return
	}
	supplyHolds.Delete(taskID)
}

func releaseAllTaskSupply() {
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
// hold, so a late failure must not restore it; the re-check after holding
// closes the race with a concurrent replacement.
var afterSupplyHoldSwap func() // test hook

func applySupplyHoldAt(t *Task, revision int64) bool {
	if t == nil {
		return false
	}
	replaced := func() bool { return revision > 0 && t.llmStateSnapshot().ChainRevision > revision }
	if replaced() {
		return false
	}
	own := &supplyHold{revision: revision}
	prev, held := supplyHolds.Swap(t.ID, own)
	if afterSupplyHoldSwap != nil {
		afterSupplyHoldSwap()
	}
	if replaced() {
		cur := t.llmStateSnapshot().ChainRevision
		if p, ok := prev.(*supplyHold); held && ok && (p.revision == 0 || p.revision >= cur) {
			supplyHolds.CompareAndSwap(t.ID, own, prev)
		} else {
			supplyHolds.CompareAndDelete(t.ID, own)
		}
		return false
	}
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
