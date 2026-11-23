package server

import (
	"errors"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

func TestTaskLLMStopLossCommittedQuotaBooksWithoutReplay(t *testing.T) {
	policy := agent.DefaultStopLossPolicy()
	policy.IdleProbeLimit = 1
	loss := agent.NewStopLossMonitor(policy)
	loss.ObserveTool("Bash", []byte(`{"command":"fixture"}`), false)
	if !loss.Recompute().Fired() {
		t.Fatal("fixture did not latch")
	}
	ctx := agent.WithModelRetryStop(t.Context(), loss)
	quota := errors.New("openai: status 402: insufficient_quota")
	provider := &scriptedLLMProvider{events: []llm.StreamEvent{{Type: llm.SETextDelta, Text: "partial"}}, err: quota}
	selections, exhausts, transitions := 0, 0, 0
	hooks := taskLLMStreamHooks{
		current: func() (taskLLMSelection, error) {
			selections++
			return taskLLMSelection{profileID: 11, provider: provider}, nil
		},
		exhaust: func(taskLLMSelection, error) (db.TaskLLMTransition, error) {
			exhausts++
			next := int64(22)
			return db.TaskLLMTransition{PreviousProfileID: 11, NextProfileID: &next, Advanced: true, Revision: 3}, nil
		},
		transition: func(taskLLMSelection, db.TaskLLMTransition, error) { transitions++ },
	}
	events, err := collectTaskLLMStream(streamTaskLLM(ctx, "7", llm.CompletionRequest{}, hooks))
	if !errors.Is(err, quota) || !isTaskLLMFailoverReady(err) || taskLLMErrorRevision(err) != 3 ||
		len(events) != 1 || events[0].Text != "partial" || selections != 1 ||
		provider.calls != 1 || exhausts != 1 || transitions != 1 {
		t.Fatalf("events=%+v err=%v selections=%d calls=%d exhausts=%d transitions=%d", events, err, selections, provider.calls, exhausts, transitions)
	}
}

func TestTaskLLMStopLossQuotaBooksFailoverWithoutReplay(t *testing.T) {
	policy := agent.DefaultStopLossPolicy()
	policy.IdleProbeLimit = 1
	loss := agent.NewStopLossMonitor(policy)
	loss.ObserveTool("Bash", []byte(`{"command":"fixture"}`), false)
	if !loss.Recompute().Fired() {
		t.Fatal("fixture did not latch")
	}
	ctx := agent.WithModelRetryStop(t.Context(), loss)
	errLookup := errors.New("LLM profile #22 is missing or invalid")
	quota := errors.New("openai: status 402: insufficient_quota")
	for _, tc := range []struct {
		name      string
		stream    bool
		exhausted bool
		stale     bool
		lookupErr bool
	}{
		{"complete fallback", false, false, false, false},
		{"stream fallback", true, false, false, false},
		{"complete chain exhausted", false, true, false, false},
		{"stream chain exhausted", true, true, false, false},
		{"complete stale, last profile gone", false, true, true, false},
		{"stream stale, last profile gone", true, true, true, false},
		{"complete stale, lookup fails", false, false, true, true},
		{"stream stale, lookup fails", true, false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := &scriptedLLMProvider{err: quota}
			second := &scriptedLLMProvider{events: []llm.StreamEvent{{Type: llm.SETextDelta, Text: "fallback"}}}
			active := int64(11)
			exhausts, transitions := 0, 0
			hooks := taskLLMStreamHooks{
				current: func() (taskLLMSelection, error) {
					if active == -1 {
						return taskLLMSelection{}, errLookup
					}
					if active == 0 {
						return taskLLMSelection{}, &taskLLMError{taskID: "7", chainExhausted: true, cause: errors.New("all selected profiles are quota exhausted")}
					}
					if active == 11 {
						return taskLLMSelection{profileID: 11, provider: first}, nil
					}
					return taskLLMSelection{profileID: 22, provider: second}, nil
				},
				exhaust: func(taskLLMSelection, error) (db.TaskLLMTransition, error) {
					exhausts++
					if tc.stale {
						active = 0
						if tc.lookupErr {
							active = -1
						}
						return db.TaskLLMTransition{PreviousProfileID: 11, Stale: true}, nil
					}
					if tc.exhausted {
						return db.TaskLLMTransition{PreviousProfileID: 11, ChainExhausted: true, Advanced: true}, nil
					}
					active = 22
					next := active
					return db.TaskLLMTransition{PreviousProfileID: 11, NextProfileID: &next, Advanced: true}, nil
				},
				transition: func(taskLLMSelection, db.TaskLLMTransition, error) { transitions++ },
			}
			var err error
			if tc.stream {
				_, err = collectTaskLLMStream(streamTaskLLM(ctx, "7", llm.CompletionRequest{}, hooks))
			} else {
				_, _, _, err = completeTaskLLM(ctx, "7", llm.CompletionRequest{}, hooks)
			}
			wantTransitions := 1
			if tc.stale {
				wantTransitions = 0
			}
			if err == nil || exhausts != 1 || transitions != wantTransitions || first.calls != 1 || second.calls != 0 {
				t.Fatalf("err=%v exhausts=%d transitions=%d calls=%d/%d", err, exhausts, transitions, first.calls, second.calls)
			}
			if tc.lookupErr {
				if !errors.Is(err, errLookup) {
					t.Fatalf("lookup error was replaced: %v", err)
				}
				return
			}
			if isTaskLLMFailoverReady(err) == tc.exhausted || isTaskLLMChainExhausted(err) != tc.exhausted {
				t.Fatalf("failoverReady=%t chainExhausted=%t", isTaskLLMFailoverReady(err), isTaskLLMChainExhausted(err))
			}
		})
	}
}

func TestTaskLLMNonStopLossCommittedQuotaSetsFailoverReady(t *testing.T) {
	// Even without stop-loss latched, a mid-stream (committed) quota failure
	// with a healthy backup profile must NOT replay the partial turn, MUST mark
	// failoverReady=true so runIntent does not freeze the whole task, and MUST
	// remain wrapped as a taskLLMError so retryableWorkerModelError stays false.
	quota := errors.New("openai: status 402: insufficient_quota")
	provider := &scriptedLLMProvider{events: []llm.StreamEvent{{Type: llm.SETextDelta, Text: "partial"}}, err: quota}
	next := int64(22)
	hooks := taskLLMStreamHooks{
		current: func() (taskLLMSelection, error) {
			return taskLLMSelection{profileID: 11, revision: 4, provider: provider}, nil
		},
		exhaust: func(taskLLMSelection, error) (db.TaskLLMTransition, error) {
			return db.TaskLLMTransition{PreviousProfileID: 11, NextProfileID: &next, Advanced: true, Revision: 4}, nil
		},
	}
	events, err := collectTaskLLMStream(streamTaskLLM(t.Context(), "9", llm.CompletionRequest{}, hooks))
	if len(events) != 1 || !errors.Is(err, quota) {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	if !isTaskLLMRuntimeError(err) || !isTaskLLMFailoverReady(err) || isTaskLLMChainExhausted(err) || taskLLMErrorRevision(err) != 4 {
		t.Fatalf("runtime=%v failoverReady=%v exhausted=%v rev=%d err=%v",
			isTaskLLMRuntimeError(err), isTaskLLMFailoverReady(err), isTaskLLMChainExhausted(err), taskLLMErrorRevision(err), err)
	}
}

