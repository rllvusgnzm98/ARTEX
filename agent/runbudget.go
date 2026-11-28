package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

type runBudgetKey struct{}

type budgetExtension struct {
	mu             sync.Mutex
	bonus          time.Duration
	maxBonus       time.Duration
	frozen         bool
	progressBonus  time.Duration
	lastProgressAt time.Time
}

const workerProgressExtendCooldown = 5 * time.Minute

type runBudget struct {
	work, hard time.Time
	reserve    time.Duration
	recovery   bool
	ext        *budgetExtension
}

func (b runBudget) currentBonus() time.Duration {
	if b.ext == nil {
		return 0
	}
	b.ext.mu.Lock()
	defer b.ext.mu.Unlock()
	return b.ext.bonus
}

func (b runBudget) workDeadline() time.Time { return b.work.Add(b.currentBonus()) }

func (b runBudget) hardDeadline() time.Time { return b.hard.Add(b.currentBonus()) }

func (b runBudget) maxHardDeadline() time.Time {
	if b.ext == nil {
		return b.hard
	}
	return b.hard.Add(b.ext.maxBonus)
}

func (b runBudget) extend(delta time.Duration) (added, total time.Duration) {
	if b.ext == nil || delta <= 0 {
		return 0, 0
	}
	b.ext.mu.Lock()
	defer b.ext.mu.Unlock()
	if b.ext.frozen {
		return 0, b.ext.bonus
	}
	rem := b.ext.maxBonus - b.ext.bonus
	if rem <= 0 {
		return 0, b.ext.bonus
	}
	if delta > rem {
		delta = rem
	}
	b.ext.bonus += delta
	return delta, b.ext.bonus
}

func freezeRunBudgetExtension(ctx context.Context) {
	b, ok := ctx.Value(runBudgetKey{}).(runBudget)
	if !ok || b.ext == nil {
		return
	}
	b.ext.mu.Lock()
	b.ext.frozen = true
	b.ext.mu.Unlock()
}

func enableRunBudgetExtension(ctx context.Context, maxBonus time.Duration) context.Context {
	b, ok := ctx.Value(runBudgetKey{}).(runBudget)
	if !ok || maxBonus <= 0 || b.work.IsZero() {
		return ctx
	}
	b.ext = &budgetExtension{maxBonus: maxBonus}
	return context.WithValue(ctx, runBudgetKey{}, b)
}

func extendRunBudgetFromContext(ctx context.Context, delta time.Duration) (time.Duration, time.Duration) {
	b, ok := ctx.Value(runBudgetKey{}).(runBudget)
	if !ok {
		return 0, 0
	}
	return b.extend(delta)
}

// ExtendWorkerProgressFromContext grants a bounded, cooldown-gated run budget
// extension when a worker achieves high-signal concrete progress (e.g. a live
// session foothold or observed evidence), capped at maxBonus/2 in total.
func ExtendWorkerProgressFromContext(ctx context.Context, delta time.Duration) (time.Duration, time.Duration) {
	return extendWorkerProgressAt(ctx, delta, time.Now())
}

func extendWorkerProgressAt(ctx context.Context, delta time.Duration, now time.Time) (time.Duration, time.Duration) {
	b, ok := ctx.Value(runBudgetKey{}).(runBudget)
	if !ok || b.ext == nil || delta <= 0 {
		return 0, 0
	}
	b.ext.mu.Lock()
	defer b.ext.mu.Unlock()
	if b.ext.frozen {
		return 0, b.ext.bonus
	}
	progressCap := b.ext.maxBonus / 2
	if progressCap <= 0 {
		return 0, b.ext.bonus
	}
	if !b.ext.lastProgressAt.IsZero() && now.Sub(b.ext.lastProgressAt) < workerProgressExtendCooldown {
		return 0, b.ext.bonus
	}
	remTotal := b.ext.maxBonus - b.ext.bonus
	remProgress := progressCap - b.ext.progressBonus
	rem := min(remTotal, remProgress)
	if rem <= 0 {
		return 0, b.ext.bonus
	}
	if delta > rem {
		delta = rem
	}
	b.ext.bonus += delta
	b.ext.progressBonus += delta
	b.ext.lastProgressAt = now
	return delta, b.ext.bonus
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
	inner llm.Provider
	calls *atomic.Int64
}

func (p *runBudgetProvider) callContext(ctx context.Context) (context.Context, context.CancelFunc, time.Time) {
	if p.calls != nil {
		p.calls.Add(1)
	}
	b, ok := ctx.Value(runBudgetKey{}).(runBudget)
	if !ok {
		return ctx, func() {}, time.Time{}
	}
	deadline := b.workDeadline()
	if b.recovery || !time.Now().Before(deadline) {
		deadline = b.hardDeadline()
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
	if b, ok := ctx.Value(runBudgetKey{}).(runBudget); ok && b.ext != nil && !b.recovery {
		if deadline := b.workDeadline(); !time.Now().Before(deadline) {
			return llm.Message{}, "", llm.Usage{}, &RunBudgetError{Deadline: deadline}
		}
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
		if b, ok := ctx.Value(runBudgetKey{}).(runBudget) ; ok && b.ext != nil && !b.recovery {
			if deadline := b.workDeadline(); !time.Now().Before(deadline) {
				yield(llm.StreamEvent{}, &RunBudgetError{Deadline: deadline})
				return
			}
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

// workDeadlineTool clamps non-write-back tool executions (notably Bash and sleep)
// to runBudget.workDeadline() during the main work phase so slow tools or sleeps
// cannot overrun workDeadline and starve the settlement reserve.
type workDeadlineTool struct {
	actool.CoreTool
}

func wrapToolsWithWorkDeadline(tools []actool.CoreTool) []actool.CoreTool {
	if len(tools) == 0 {
		return tools
	}
	out := make([]actool.CoreTool, len(tools))
	for i, t := range tools {
		if t == nil || isWriteBackTool(t.Name()) {
			out[i] = t
			continue
		}
		out[i] = &workDeadlineTool{CoreTool: t}
	}
	return out
}

func (t *workDeadlineTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	b, ok := ctx.Value(runBudgetKey{}).(runBudget)
	if !ok || b.recovery || b.work.IsZero() {
		return t.CoreTool.Call(ctx, in, tc)
	}
	deadline := b.workDeadline()
	if deadline.IsZero() {
		return t.CoreTool.Call(ctx, in, tc)
	}
	callCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	return t.CoreTool.Call(callCtx, in, tc)
}
