package agent

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/norma/llm"
)

type runBudgetKey struct{}

type runBudget struct {
	work, hard time.Time
	reserve    time.Duration
	recovery   bool
}

func withRunBudget(ctx context.Context, start time.Time, total, reserve time.Duration) (context.Context, time.Duration) {
	if total <= 0 {
		return ctx, total
	}
	reserve = min(max(0, reserve), total/4)
	b := runBudget{work: start.Add(total - reserve), hard: start.Add(total), reserve: reserve}
	return context.WithValue(ctx, runBudgetKey{}, b), total - reserve
}

type RunBudgetError struct {
	Deadline time.Time
}

func (e *RunBudgetError) Error() string {
	return fmt.Sprintf("worker run budget expired at %s", e.Deadline.Format(time.RFC3339Nano))
}
func (e *RunBudgetError) Unwrap() error { return context.DeadlineExceeded }

func isRunBudgetError(err error) bool {
	var budget *RunBudgetError
	return errors.As(err, &budget)
}

type runBudgetProvider struct {
	inner         llm.Provider
	calls         *atomic.Int64
	loss          *StopLossMonitor
	postLossCalls atomic.Int64
}

const maxPostStopLossTurns = 3

func (p *runBudgetProvider) postStopLossLimitReached() bool {
	return p.loss.Fired() && p.postLossCalls.Add(1) > maxPostStopLossTurns
}

func (p *runBudgetProvider) callContext(ctx context.Context) (context.Context, context.CancelFunc, time.Time) {
	if p.calls != nil {
		p.calls.Add(1)
	}
	b, ok := ctx.Value(runBudgetKey{}).(runBudget)
	if !ok {
		return ctx, func() {}, time.Time{}
	}
	deadline := b.work
	if p.loss.Fired() || b.recovery || !time.Now().Before(b.work) {
		deadline = b.hard
	}
	callCtx, cancel := context.WithDeadline(ctx, deadline)
	return callCtx, cancel, deadline
}

func runDeadlineError(parent, call context.Context, deadline time.Time, err error) error {
	if !deadline.IsZero() && parent.Err() == nil && call.Err() != nil {
		return &RunBudgetError{Deadline: deadline}
	}
	return err
}

func (p *runBudgetProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	if err := ctx.Err(); err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	if p.postStopLossLimitReached() {
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(p.loss.Verdict().Message())}}, "end_turn", llm.Usage{}, nil
	}
	callCtx, cancel, deadline := p.callContext(ctx)
	defer cancel()
	msg, stop, usage, err := p.inner.Complete(callCtx, req)
	return msg, stop, usage, runDeadlineError(ctx, callCtx, deadline, err)
}

func (p *runBudgetProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		if err := ctx.Err(); err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		if p.postStopLossLimitReached() {
			if yield(llm.StreamEvent{Type: llm.SEMessageStart}, nil) &&
				yield(llm.StreamEvent{Type: llm.SETextDelta, Text: p.loss.Verdict().Message()}, nil) &&
				yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil) {
				yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
			}
			return
		}
		callCtx, cancel, deadline := p.callContext(ctx)
		defer cancel()
		for ev, err := range p.inner.Stream(callCtx, req) {
			err = runDeadlineError(ctx, callCtx, deadline, err)
			if !yield(ev, err) || err != nil {
				return
			}
		}
		if err := runDeadlineError(ctx, callCtx, deadline, nil); err != nil {
			yield(llm.StreamEvent{}, err)
		}
	}
}
