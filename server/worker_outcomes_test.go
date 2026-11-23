package server

import (
	"context"
	"errors"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/norma/harness"
)

func TestWorkerTerminationOutcome(t *testing.T) {
	stopped := agent.StopLossVerdict{Kind: agent.StopLossNoProgress}
	for _, tc := range []struct {
		reason           harness.TerminalReason
		err              error
		verdict          agent.StopLossVerdict
		writes           agent.WriteCounts
		class, subreason string
	}{
		{harness.ReasonCompleted, nil, agent.StopLossVerdict{}, agent.WriteCounts{}, "executed", "completed"},
		{harness.ReasonMaxTurns, nil, agent.StopLossVerdict{}, agent.WriteCounts{}, "budget_exhausted", "max_turns"},
		{harness.ReasonStopHookPrevented, nil, stopped, agent.WriteCounts{}, "stop_loss", "no_progress"},
		{harness.ReasonStopHookPrevented, nil, stopped, agent.WriteCounts{Facts: 1, Failures: 1}, "persistence_failed", "evidence_write"},
		{harness.ReasonAbortedStreaming, context.Canceled, stopped, agent.WriteCounts{}, "cancelled", "context_cancelled"},
	} {
		class, reason := workerTerminationOutcome(tc.reason, tc.err, tc.verdict, tc.writes, nil)
		if class != tc.class || reason != tc.subreason {
			t.Errorf("terminal %s: got %s/%s, want %s/%s", tc.reason, class, reason, tc.class, tc.subreason)
		}
	}
}

func TestDetachedWorkCompletionReportsOnce(t *testing.T) {
	e := &Engine{work: make(map[int64]*workExecution)}
	_, cancel := context.WithCancelCause(t.Context())
	e.registerWork(1, cancel)
	done := e.work[1].done
	_, complete := e.detachWork(1)
	want := errors.New("first completion")
	complete(want)
	if got := <-done; got != want {
		t.Fatalf("first completion = %v, want %v", got, want)
	}
	complete(nil)
	select {
	case got := <-done:
		t.Errorf("unexpected second result: %v", got)
	default:
	}
}
