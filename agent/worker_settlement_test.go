package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

func budgetToolMessage(name string) llm.Message {
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "budget-write", Name: name, Input: json.RawMessage(`{"summary":"settlement evidence","confidence":"observed"}`)}}}
}

func TestWorkerPostStopLossBound(t *testing.T) {
	for _, mode := range []string{"denied_stream", "denied_complete", "record_fact_loop", "hard_deadline", "parent_deadline", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "parent_deadline" {
				var cancelParent context.CancelFunc
				ctx, cancelParent = context.WithTimeout(ctx, 200*time.Millisecond)
				defer cancelParent()
			}
			duration := 3 * time.Second
			if mode == "hard_deadline" {
				duration = 200 * time.Millisecond
			}
			ctx, work := withRunBudget(ctx, time.Now(), duration, duration/4)
			policy := tightPolicy()
			policy.IdleProbeLimit = 1
			loss := NewStopLossMonitor(policy)
			probes, facts, calls, blocked, results := 0, 0, 0, 0, 0
			mockTool := func(name string, runs *int) actool.CoreTool {
				return actool.Build(actool.Spec{Name: name, Schema: obj(map[string]any{}), RawInput: true,
					Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
						*runs++
						return actool.Text("fixture"), nil
					}})
			}
			fake := budgetFakeProvider{complete: func(call context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
				calls++
				if calls == 1 {
					msg := budgetToolMessage("Bash")
					msg.Content[0].Input = json.RawMessage(`{"command":"fixture"}`)
					return msg, "tool_use", llm.Usage{}, nil
				}
				switch mode {
				case "hard_deadline", "parent_deadline", "cancel":
					if mode == "cancel" {
						cancel()
					}
					<-call.Done()
					return llm.Message{}, "", llm.Usage{}, call.Err()
				case "record_fact_loop":
					return budgetToolMessage("record_fact"), "tool_use", llm.Usage{}, nil
				default:
					return budgetToolMessage("Bash"), "tool_use", llm.Usage{}, nil
				}
			}}
			opts := agentcore.Options{Provider: &runBudgetProvider{inner: fake, loss: loss}, Hooks: WrapStopLoss(nil, loss),
				Tools:          []actool.CoreTool{mockTool("Bash", &probes), mockTool("record_fact", &facts)},
				PermissionMode: permission.ModeBypass, NonStreaming: mode != "denied_stream", MaxDuration: work, DisableBackgroundTasks: true}
			session := agentcore.NewSession(opts)
			defer session.Close()
			start := time.Now()
			reason, err := captureWorkerSession(ctx, session, "fixture", func(a db.Activity) {
				if a.Kind == "result" {
					results++
				}
				if a.Kind == "tool_result" && strings.Contains(string(a.Metadata), "policy_blocked") {
					blocked++
				}
			})
			if !loss.Fired() || probes != 1 || results != 1 {
				t.Fatalf("verdict=%v probes=%d results=%d reason=%s err=%v", loss.Verdict(), probes, results, reason, err)
			}
			switch mode {
			case "hard_deadline":
				if !isRunBudgetError(err) || reason != harness.ReasonTimeout || calls != 2 || time.Since(start) > time.Second {
					t.Fatalf("hard deadline: reason=%s calls=%d elapsed=%s err=%v", reason, calls, time.Since(start), err)
				}
			case "parent_deadline":
				if !errors.Is(err, context.DeadlineExceeded) || isRunBudgetError(err) || calls != 2 || time.Since(start) > time.Second {
					t.Fatalf("parent deadline: calls=%d elapsed=%s err=%v", calls, time.Since(start), err)
				}
			case "cancel":
				if !errors.Is(err, context.Canceled) || calls != 2 || time.Since(start) > time.Second {
					t.Fatalf("cancel: calls=%d elapsed=%s err=%v", calls, time.Since(start), err)
				}
			default:
				wantFacts, wantBlocked := 0, maxPostStopLossTurns
				if mode == "record_fact_loop" {
					wantFacts, wantBlocked = maxPostStopLossTurns, 0
				}
				if err != nil || reason != harness.ReasonStopHookPrevented || calls != 1+maxPostStopLossTurns || facts != wantFacts || blocked != wantBlocked {
					t.Fatalf("reason=%s calls=%d facts=%d blocked=%d err=%v", reason, calls, facts, blocked, err)
				}
			}
		})
	}
}

func TestWorkerRecoverySettlement(t *testing.T) {
	for _, mode := range []string{"work", "work_stream", "hard", "call_timeout", "zero", "short", "unlimited", "cancel", "no_transcript", "turn_cap", "recovery_error"} {
		t.Run(mode, func(t *testing.T) {
			_, store := retentionStore(t)
			tsx := NewToolSet(store, "budget-test")
			ctx, work := withRunBudget(t.Context(), time.Now().Add(-18*time.Second+100*time.Millisecond), 24*time.Second, 6*time.Second)
			if mode == "zero" {
				ctx, work = withRunBudget(t.Context(), time.Now(), time.Second, 0)
			}
			if mode == "short" {
				ctx, work = withRunBudget(t.Context(), time.Now(), time.Second, 250*time.Millisecond)
			}
			if mode == "unlimited" {
				ctx, work = withRunBudget(t.Context(), time.Now(), 0, 0)
			}
			if mode == "cancel" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			calls := 0
			fake := budgetFakeProvider{complete: func(call context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
				calls++
				if calls == 1 {
					if mode == "zero" || mode == "short" || mode == "unlimited" {
						return llm.Message{}, "", llm.Usage{}, &CallTimeoutError{}
					}
					<-call.Done()
					return llm.Message{}, "", llm.Usage{}, call.Err()
				}
				for _, tool := range req.Tools {
					if tool.Name == "Bash" {
						t.Error("Bash exposed in recovery")
					}
				}
				foundHistory, foundPrompt := false, false
				for _, message := range req.Messages {
					foundHistory = foundHistory || strings.Contains(message.Text(), "initial evidence")
					foundPrompt = foundPrompt || strings.Contains(message.Text(), "checkpoint existing evidence")
				}
				if !foundHistory || !foundPrompt {
					t.Error("recovery lost history or settlement prompt")
				}
				if mode == "hard" {
					<-call.Done()
					return llm.Message{}, "", llm.Usage{}, call.Err()
				}
				if mode == "recovery_error" {
					return llm.Message{}, "", llm.Usage{}, errors.New("settlement provider failed")
				}
				if calls == 2 || mode == "turn_cap" {
					return budgetToolMessage("record_fact"), "tool_use", llm.Usage{}, nil
				}
				return assistantText("saved"), "end_turn", llm.Usage{}, nil
			}}
			var provider llm.Provider = fake
			if mode == "call_timeout" {
				provider = &callTimeoutProvider{inner: provider, timeout: 20 * time.Millisecond}
			}
			settle := &harness.Settlement{Prompt: "checkpoint existing evidence", MaxTurns: 2, DisabledTools: []string{"Bash"}}
			opts := agentcore.Options{Provider: &runBudgetProvider{inner: provider}, Tools: []actool.CoreTool{tsx.recordFact(), actool.NewBash()}, NonStreaming: true, PermissionMode: permission.ModeBypass, MaxDuration: work, Settlement: settle, Transcript: transcript.NewStore(t.TempDir()), SessionID: "budget-test", DisableBackgroundTasks: true}
			if mode == "work_stream" {
				opts.NonStreaming = false
			}
			if mode == "no_transcript" {
				opts.Transcript = nil
			}
			s := agentcore.NewSession(opts)
			defer s.Close()
			start := time.Now()
			_, reason, err := captureRunSession(ctx, s, "initial evidence", nil)
			w := NewWorker(provider, "fake", t.TempDir(), nil, 0, 0)
			w.recoverSettlement(ctx, s, opts, settle, err, tsx, nil)
			state := IntentStateAfterRun(reason, err, StopLossVerdict{})
			wantState, wantWrites := "exhausted", 1
			if mode == "call_timeout" || mode == "zero" || mode == "short" || mode == "unlimited" {
				wantState = "open"
			}
			if mode == "hard" || mode == "zero" || mode == "short" || mode == "unlimited" || mode == "cancel" || mode == "recovery_error" {
				wantWrites = 0
			}
			if mode == "turn_cap" {
				wantWrites = 2
			}
			if mode == "cancel" {
				wantState = "blocked"
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("err=%v", err)
				}
			}
			if state != wantState || tsx.Writes().Facts != wantWrites {
				t.Fatalf("state=%s writes=%+v err=%v calls=%d", state, tsx.Writes(), err, calls)
			}
			if wantWrites > 0 {
				facts, e := store.ListByKind(db.KindFact, 100)
				persisted := 0
				for _, fact := range facts {
					var payload map[string]any
					if json.Unmarshal(fact.Payload, &payload) == nil && payload["summary"] == "settlement evidence" {
						persisted++
					}
				}
				if e != nil || persisted != wantWrites {
					t.Fatalf("persisted=%d err=%v", persisted, e)
				}
			}
			if mode == "zero" || mode == "short" || mode == "unlimited" || mode == "cancel" {
				if calls > 1 {
					t.Fatalf("unexpected recovery calls=%d", calls)
				}
			}
			if b, ok := ctx.Value(runBudgetKey{}).(runBudget); ok && time.Now().After(b.hard.Add(300*time.Millisecond)) {
				t.Fatalf("hard deadline exceeded, elapsed=%s", time.Since(start))
			}
			t.Logf("state=%s calls=%d writes=%s elapsed=%s", state, calls, tsx.Writes(), time.Since(start))
		})
	}
}

func TestWorkerSDKBoundarySettlement(t *testing.T) {
	ctx, work := withRunBudget(t.Context(), time.Now(), 400*time.Millisecond, 100*time.Millisecond)
	calls := 0
	p := budgetFakeProvider{complete: func(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		calls++
		if calls == 1 {
			return budgetToolMessage("probe"), "tool_use", llm.Usage{}, nil
		}
		for _, tool := range req.Tools {
			if tool.Name == "probe" {
				t.Error("disabled tool in SDK settlement")
			}
		}
		return assistantText("SDK checkpoint"), "end_turn", llm.Usage{}, nil
	}}
	probe := actool.Build(actool.Spec{Name: "probe", Schema: obj(map[string]any{}), Run: func(ctx context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
		<-ctx.Done()
		return actool.Text("interrupted"), nil
	}})
	opts := agentcore.Options{Provider: &runBudgetProvider{inner: p}, Tools: []actool.CoreTool{probe}, NonStreaming: true, PermissionMode: permission.ModeBypass, MaxDuration: work, Settlement: &harness.Settlement{Prompt: "checkpoint", MaxTurns: 1, DisabledTools: []string{"probe"}}, DisableBackgroundTasks: true}
	text, reason, err := captureRun(ctx, opts, "start", nil)
	if err != nil || reason != harness.ReasonTimeout || text != "SDK checkpoint" || calls != 2 {
		t.Fatalf("text=%q reason=%s err=%v calls=%d", text, reason, err, calls)
	}
}

func TestWorkerCallTimeoutRecoveryPG(t *testing.T) {
	d, store := retentionStore(t)
	var taskID int64
	if err := d.QueryRow(`SELECT id FROM tasks WHERE exploration_id=$1`, store.ID()).Scan(&taskID); err != nil {
		t.Fatal(err)
	}
	id, err := store.AddIntent(map[string]any{"summary": "settlement fixture"}, 0, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := store.GetNode(id)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	fake := budgetFakeProvider{complete: func(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		calls++
		b, ok := ctx.Value(runBudgetKey{}).(runBudget)
		if !ok || (!b.recovery && b.hard.Sub(b.work) != 6*time.Second) {
			t.Errorf("worker budget=%+v", b)
		}
		if calls == 1 {
			<-ctx.Done()
			return llm.Message{}, "", llm.Usage{}, ctx.Err()
		}
		if !b.recovery {
			t.Error("missing recovery phase")
		}
		if calls == 2 {
			return budgetToolMessage("record_fact"), "tool_use", llm.Usage{}, nil
		}
		return assistantText("saved"), "end_turn", llm.Usage{}, nil
	}}
	dir := t.TempDir()
	w := NewWorker(&callTimeoutProvider{inner: fake, timeout: 40 * time.Millisecond}, "fake", dir, transcript.NewStore(dir), 128000, 10)
	w.SetRunTimeout(24 * time.Second)
	w.SetSettleTimeout(6 * time.Second)
	w.SetNonStreaming(func() bool { return true })
	reason, writes, err := w.Execute(t.Context(), "budget-worker", taskID, nil, store, intent, nil, nil, nil, nil)
	if !IsCallTimeout(err) || writes.Facts != 1 || calls != 3 || IntentStateAfterRun(reason, err, StopLossVerdict{}) != "open" {
		t.Fatalf("reason=%s writes=%s calls=%d err=%v", reason, writes, calls, err)
	}
}

func TestWorkerRunBudgetExpiryPG(t *testing.T) {
	d, store := retentionStore(t)
	var taskID int64
	if err := d.QueryRow(`SELECT id FROM tasks WHERE exploration_id=$1`, store.ID()).Scan(&taskID); err != nil {
		t.Fatal(err)
	}
	id, err := store.AddIntent(map[string]any{"summary": "short run budget"}, 0, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := store.GetNode(id)
	if err != nil {
		t.Fatal(err)
	}
	w := NewWorker(hangProv{}, "fake", t.TempDir(), nil, 128000, 10)
	w.SetRunTimeout(200 * time.Millisecond)
	w.SetSettleTimeout(50 * time.Millisecond)
	w.SetNonStreaming(func() bool { return true })
	start := time.Now()
	reason, writes, err := w.Execute(t.Context(), "budget-worker", taskID, nil, store, intent, nil, nil, nil, nil)
	if !isRunBudgetError(err) || reason != harness.ReasonTimeout || writes.Total() != 0 || time.Since(start) > time.Second {
		t.Fatalf("reason=%s writes=%s err=%v elapsed=%s", reason, writes, err, time.Since(start))
	}
	if state := IntentStateAfterRun(reason, err, StopLossVerdict{}); state != "exhausted" {
		t.Fatalf("state=%s", state)
	}
	if result := SettleWorkerRun(reason, err); result.IntentState != "exhausted" || result.TerminalKind != TerminalBudgetExhausted {
		t.Fatalf("result=%+v", result)
	}
}
