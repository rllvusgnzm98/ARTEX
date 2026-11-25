package agent

import (
	"context"
	"errors"
	"iter"
	"testing"
	"time"

	"github.com/Autumn-27/norma/llm"
)

type budgetFakeProvider struct {
	complete func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error)
}

func (p budgetFakeProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return p.complete(ctx, req)
}

func (p budgetFakeProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		msg, stop, _, err := p.complete(ctx, req)
		if err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		if !yield(llm.StreamEvent{Type: llm.SEMessageStart}, nil) {
			return
		}
		for _, block := range msg.Content {
			if block.Type == llm.BlockToolUse {
				if !yield(llm.StreamEvent{Type: llm.SEToolUseStart, ToolID: block.ID, ToolName: block.Name}, nil) {
					return
				}
				if !yield(llm.StreamEvent{Type: llm.SEToolInputJSON, Text: string(block.Input)}, nil) {
					return
				}
			} else if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: block.Text}, nil) {
				return
			}
		}
		if !yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: stop}, nil) {
			return
		}
		yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}

func TestWorkerBudgetReserve(t *testing.T) {
	start := time.Now()
	for _, tc := range []struct{ total, reserve, work time.Duration }{
		{1200 * time.Second, 120 * time.Second, 1080 * time.Second},
		{40 * time.Second, 120 * time.Second, 30 * time.Second},
		{time.Second, -time.Second, time.Second},
		{time.Second, 0, time.Second},
		{0, time.Second, 0},
	} {
		ctx, work := withRunBudget(t.Context(), start, tc.total, tc.reserve)
		if work != tc.work {
			t.Fatalf("work=%s want=%s", work, tc.work)
		}
		b, ok := ctx.Value(runBudgetKey{}).(runBudget)
		if tc.total == 0 {
			if ok {
				t.Fatal("unlimited run acquired deadline")
			}
		} else if !ok || !b.work.Equal(start.Add(tc.work)) || !b.hard.Equal(start.Add(tc.total)) {
			t.Fatalf("budget=%+v", b)
		}
	}
}

func TestRunBudgetProvider(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, mode := range []string{"work", "hard", "call_timeout", "cancel", "none", "error"} {
			t.Run(mode+map[bool]string{false: "/complete", true: "/stream"}[stream], func(t *testing.T) {
				ctx := t.Context()
				var cancel context.CancelFunc = func() {}
				defer func() { cancel() }()
				var inner llm.Provider = hangProv{}
				if mode != "none" {
					ctx, _ = withRunBudget(ctx, time.Now(), 120*time.Millisecond, 30*time.Millisecond)
				}
				if mode == "hard" {
					b := ctx.Value(runBudgetKey{}).(runBudget)
					b.work = time.Now().Add(-time.Millisecond)
					b.hard = time.Now().Add(30 * time.Millisecond)
					ctx = context.WithValue(ctx, runBudgetKey{}, b)
				}
				if mode == "call_timeout" {
					inner = &callTimeoutProvider{inner: inner, timeout: 10 * time.Millisecond}
				}
				if mode == "cancel" {
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				}
				sentinel := errors.New("provider failure")
				if mode == "none" || mode == "error" {
					inner = budgetFakeProvider{complete: func(call context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
						if mode == "none" && call != ctx {
							t.Error("no-budget context changed")
						}
						if mode == "error" {
							return llm.Message{}, "", llm.Usage{}, sentinel
						}
						return assistantText("done"), "end_turn", llm.Usage{}, nil
					}}
				}
				p := &runBudgetProvider{inner: inner}
				var err error
				if stream {
					for _, e := range p.Stream(ctx, llm.CompletionRequest{}) {
						err = e
					}
				} else {
					_, _, _, err = p.Complete(ctx, llm.CompletionRequest{})
				}
				switch mode {
				case "work", "hard":
					if !isRunBudgetError(err) || IsCallTimeout(err) {
						t.Fatalf("err=%v", err)
					}
				case "call_timeout":
					if !IsCallTimeout(err) || isRunBudgetError(err) {
						t.Fatalf("err=%v", err)
					}
				case "cancel":
					if !errors.Is(err, context.Canceled) || isRunBudgetError(err) {
						t.Fatalf("err=%v", err)
					}
				case "error":
					if err != sentinel {
						t.Fatalf("err=%v", err)
					}
				case "none":
					if err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}

func TestRunBudgetDynamicExtensionPreservesReserveAndExtendsDeadlines(t *testing.T) {
	start := time.Now()
	total, reserve := 20*time.Minute, 2*time.Minute
	ctx, work := withRunBudget(t.Context(), start, total, reserve)
	if work != 18*time.Minute {
		t.Fatalf("initial work=%s, want 18m", work)
	}
	ctx = enableRunBudgetExtension(ctx, total)
	b, ok := ctx.Value(runBudgetKey{}).(runBudget)
	if !ok {
		t.Fatal("missing runBudget in context")
	}
	// Crucial compatibility invariant: b.hard - b.work stays == reserve.
	if b.hard.Sub(b.work) != reserve {
		t.Fatalf("b.hard - b.work = %s, want %s", b.hard.Sub(b.work), reserve)
	}
	added, totalBonus := extendRunBudgetFromContext(ctx, 10*time.Minute)
	if added != 10*time.Minute || totalBonus != 10*time.Minute {
		t.Fatalf("first extend = (%s, %s), want (10m, 10m)", added, totalBonus)
	}
	if !b.workDeadline().Equal(start.Add(28*time.Minute)) || !b.hardDeadline().Equal(start.Add(30*time.Minute)) {
		t.Fatalf("extended deadlines wrong: work=%s hard=%s", b.workDeadline(), b.hardDeadline())
	}
	// Cap at maxBonus (20m total extension).
	added2, totalBonus2 := extendRunBudgetFromContext(ctx, 15*time.Minute)
	if added2 != 10*time.Minute || totalBonus2 != 20*time.Minute {
		t.Fatalf("capped extend = (%s, %s), want (10m, 20m)", added2, totalBonus2)
	}
}

func TestRunBudgetFreezeStopsSettlementExtensions(t *testing.T) {
	start := time.Now()
	total, reserve := 20*time.Minute, 2*time.Minute
	ctx, _ := withRunBudget(t.Context(), start, total, reserve)
	ctx = enableRunBudgetExtension(ctx, total)

	if added, totalBonus := extendRunBudgetFromContext(ctx, 10*time.Minute); added != 10*time.Minute || totalBonus != 10*time.Minute {
		t.Fatalf("pre-freeze extend = (%s, %s), want (10m, 10m)", added, totalBonus)
	}

	freezeRunBudgetExtension(ctx)

	if added, totalBonus := extendRunBudgetFromContext(ctx, 10*time.Minute); added != 0 || totalBonus != 10*time.Minute {
		t.Fatalf("post-freeze extend = (%s, %s), want (0, 10m)", added, totalBonus)
	}
	if added, totalBonus := ExtendWorkerProgressFromContext(ctx, 5*time.Minute); added != 0 || totalBonus != 10*time.Minute {
		t.Fatalf("post-freeze progress extend = (%s, %s), want (0, 10m)", added, totalBonus)
	}
}

func TestRunBudgetProgressExtensionCooldownAndSubCap(t *testing.T) {
	start := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	total, reserve := 20*time.Minute, 2*time.Minute
	ctx, _ := withRunBudget(t.Context(), start, total, reserve)
	ctx = enableRunBudgetExtension(ctx, total) // progressCap = 10m

	now := start.Add(2 * time.Minute)
	if added, tot := extendWorkerProgressAt(ctx, 5*time.Minute, now); added != 5*time.Minute || tot != 5*time.Minute {
		t.Fatalf("first progress = (%s, %s), want (5m, 5m)", added, tot)
	}
	// Within 5m cooldown -> blocked.
	if added, tot := extendWorkerProgressAt(ctx, 5*time.Minute, now.Add(4*time.Minute)); added != 0 || tot != 5*time.Minute {
		t.Fatalf("within cooldown = (%s, %s), want (0, 5m)", added, tot)
	}
	// After 5m cooldown -> granted up to 10m progress sub-cap.
	if added, tot := extendWorkerProgressAt(ctx, 5*time.Minute, now.Add(5*time.Minute)); added != 5*time.Minute || tot != 10*time.Minute {
		t.Fatalf("second progress = (%s, %s), want (5m, 10m)", added, tot)
	}
	// Progress sub-cap exhausted -> 0, even after another cooldown.
	if added, tot := extendWorkerProgressAt(ctx, 5*time.Minute, now.Add(15*time.Minute)); added != 0 || tot != 10*time.Minute {
		t.Fatalf("beyond subcap = (%s, %s), want (0, 10m)", added, tot)
	}
	// Finding extension still gets the remaining 10m out of 20m maxBonus.
	if added, tot := extendRunBudgetFromContext(ctx, 10*time.Minute); added != 10*time.Minute || tot != 20*time.Minute {
		t.Fatalf("remaining finding budget = (%s, %s), want (10m, 20m)", added, tot)
	}
}
