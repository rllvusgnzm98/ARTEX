package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

func TestWorkerJoinsCancelledRecordFact(t *testing.T) {
	d, store := retentionStore(t)
	iid, err := store.AddIntent(map[string]any{"summary": "blocked fact"}, 0, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := store.GetNode(iid)
	if err != nil {
		t.Fatal(err)
	}
	locker, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Rollback()
	if _, err := locker.Exec("LOCK TABLE exploration_edges IN EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	policy := tightPolicy()
	loss := NewStopLossMonitor(policy)
	loss.ObserveTool("Bash", []byte(`{"command":"fixture"}`), false)
	loss.ObserveTool("Bash", []byte(`{"command":"fixture"}`), false)
	if !loss.Recompute().Fired() {
		t.Fatal("fixture did not latch")
	}
	fake := budgetFakeProvider{complete: func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		msg := budgetToolMessage("record_fact")
		msg.Content[0].Input, _ = json.Marshal(map[string]any{"summary": "cancelled fact", "intent_id": iid})
		return msg, "tool_use", llm.Usage{}, nil
	}}
	worker := NewWorker(fake, "fixture", t.TempDir(), nil, 0, 0)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	type result struct {
		writes WriteCounts
		err    error
	}
	done := make(chan result, 1)
	go func() {
		_, writes, err := worker.Execute(ctx, "fixture", 0, nil, store, intent, WrapStopLoss(nil, loss), nil, nil, nil)
		done <- result{writes, err}
	}()
	for {
		var waiting bool
		if err := d.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_locks
WHERE relation='exploration_edges'::regclass AND mode='RowExclusiveLock' AND NOT granted)`).Scan(&waiting); err != nil {
			t.Fatalf("record_fact never reached the link: %v", err)
		}
		if waiting {
			break
		}
		select {
		case got := <-done:
			t.Fatalf("worker stopped before reaching the link: %+v", got)
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	select {
	case got := <-done:
		if !errors.Is(got.err, context.Canceled) || got.writes != (WriteCounts{Failures: 1}) {
			t.Fatalf("cancelled worker: err=%v writes=%#v", got.err, got.writes)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled worker did not finish with the edge lock still held")
	}
	if err := locker.Rollback(); err != nil {
		t.Fatal(err)
	}
	if ids, err := store.FactsYielded(iid); err != nil || len(ids) != 0 {
		t.Fatalf("unexpected persisted evidence: %v, %v", ids, err)
	}
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
					if a.IsError {
						t.Error("captured policy block had is_error=true")
					}
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

func TestSettlementTransientRetrySucceeds(t *testing.T) {
	origBackoffs, origMinRemain := settlementRetryBackoffs, settlementMinRetryRemain
	settlementRetryBackoffs = []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond}
	settlementMinRetryRemain = 500 * time.Millisecond
	t.Cleanup(func() {
		settlementRetryBackoffs, settlementMinRetryRemain = origBackoffs, origMinRemain
	})

	_, store := retentionStore(t)
	tsx := NewToolSet(store, "retry-worker")
	ctx, work := withRunBudget(t.Context(), time.Now().Add(-18*time.Second+100*time.Millisecond), 28*time.Second, 10*time.Second)

	calls := 0
	fake := budgetFakeProvider{complete: func(call context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		calls++
		switch calls {
		case 1:
			<-call.Done()
			return llm.Message{}, "", llm.Usage{}, call.Err()
		case 2:
			return llm.Message{}, "", llm.Usage{}, fmt.Errorf("stream failed: %w", io.ErrUnexpectedEOF)
		case 3:
			return llm.Message{}, "", llm.Usage{}, errors.New("status 503: service unavailable")
		case 4:
			return budgetToolMessage("record_fact"), "tool_use", llm.Usage{}, nil
		default:
			return assistantText("saved after retries"), "end_turn", llm.Usage{}, nil
		}
	}}
	settle := &harness.Settlement{Prompt: "checkpoint existing evidence", MaxTurns: 2, DisabledTools: []string{"Bash"}}
	opts := agentcore.Options{
		Provider: &runBudgetProvider{inner: fake}, Tools: []actool.CoreTool{tsx.recordFact(), actool.NewBash()},
		NonStreaming: true, PermissionMode: permission.ModeBypass, MaxDuration: work, Settlement: settle,
		Transcript: transcript.NewStore(t.TempDir()), SessionID: "retry-test", DisableBackgroundTasks: true,
	}
	s := agentcore.NewSession(opts)
	defer s.Close()
	_, _, runErr := captureRunSession(ctx, s, "initial evidence", nil)
	w := NewWorker(fake, "fake", t.TempDir(), nil, 0, 0)
	recErr := w.recoverSettlement(ctx, s, opts, settle, runErr, tsx, nil)
	if recErr != nil {
		t.Fatalf("expected transient settlement retries to succeed, got recErr=%v (calls=%d)", recErr, calls)
	}
	if tsx.Writes().Facts != 1 || calls < 4 {
		t.Fatalf("writes=%+v calls=%d, want 1 fact written after transient retries", tsx.Writes(), calls)
	}
}

func TestSettlementTransientExhaustedWritesPartialProgressAndReturnsTransientError(t *testing.T) {
	origBackoffs, origMinRemain := settlementRetryBackoffs, settlementMinRetryRemain
	settlementRetryBackoffs = []time.Duration{10 * time.Millisecond, 10 * time.Millisecond}
	settlementMinRetryRemain = 500 * time.Millisecond
	t.Cleanup(func() {
		settlementRetryBackoffs, settlementMinRetryRemain = origBackoffs, origMinRemain
	})

	d, store := retentionStore(t)
	var taskID int64
	if err := d.QueryRow(`SELECT id FROM tasks WHERE exploration_id=$1`, store.ID()).Scan(&taskID); err != nil {
		t.Fatal(err)
	}
	iid, err := store.AddIntent(map[string]any{"summary": "transient settlement fallback fixture"}, 0, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := store.GetNode(iid)
	if err != nil {
		t.Fatal(err)
	}

	calls := 0
	fake := budgetFakeProvider{complete: func(call context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		calls++
		b, _ := call.Value(runBudgetKey{}).(runBudget)
		if !b.recovery {
			if calls == 1 {
				return llm.Message{
					Role: llm.RoleAssistant,
					Content: []llm.ContentBlock{{
						Type:  llm.BlockToolUse,
						ID:    "probe-1",
						Name:  "Bash",
						Input: json.RawMessage(`{"command":"echo observed-port-8080-open"}`),
					}},
				}, "tool_use", llm.Usage{}, nil
			}
			// Wait for main run budget expiry so recovery settlement triggers.
			<-call.Done()
			return llm.Message{}, "", llm.Usage{}, call.Err()
		}
		// All settlement attempts fail with a transient connection error.
		return llm.Message{}, "", llm.Usage{}, errors.New("dial tcp 127.0.0.1:443: connection refused")
	}}
	dir := t.TempDir()
	w := NewWorker(fake, "fake", dir, transcript.NewStore(dir), 128000, 10)
	// work = 1s, reserve = 6s (total = 7s; reserve capped at total/4 -> use 24s total, 6s reserve?
	// No: use CallTimeoutError on turn 2 so main run ends immediately and recovery has full 6s reserve!)
	calls = 0
	fakeCallTO := budgetFakeProvider{complete: func(call context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		calls++
		b, _ := call.Value(runBudgetKey{}).(runBudget)
		if !b.recovery {
			if calls == 1 {
				return llm.Message{
					Role: llm.RoleAssistant,
					Content: []llm.ContentBlock{{
						Type:  llm.BlockToolUse,
						ID:    "probe-1",
						Name:  "Bash",
						Input: json.RawMessage(`{"command":"echo observed-port-8080-open"}`),
					}},
				}, "tool_use", llm.Usage{}, nil
			}
			return llm.Message{}, "", llm.Usage{}, &CallTimeoutError{Provider: "fake", Model: "fake", Timeout: time.Second}
		}
		return llm.Message{}, "", llm.Usage{}, errors.New("dial tcp 127.0.0.1:443: connection refused")
	}}
	_ = fake
	w = NewWorker(fakeCallTO, "fake", dir, transcript.NewStore(dir), 128000, 10)
	w.SetRunTimeout(28 * time.Second)
	w.SetSettleTimeout(7 * time.Second)
	w.SetNonStreaming(func() bool { return true })

	_, writes, runErr := w.Execute(t.Context(), "fallback-worker", taskID, nil, store, intent, nil, nil, nil, nil)
	if !IsSettlementTransientError(runErr) {
		t.Fatalf("expected SettlementTransientError, got err=%v", runErr)
	}
	var ste *SettlementTransientError
	if !errors.As(runErr, &ste) || ste.BudgetErr == nil || ste.RecoveryErr == nil {
		t.Fatalf("SettlementTransientError fields missing: %#v", ste)
	}
	if !IsCallTimeout(runErr) {
		t.Fatalf("Unwrap should preserve underlying BudgetErr (CallTimeoutError), got %v", runErr)
	}
	// 2 main calls + 1 initial settlement attempt + 2 retries = 5 total calls.
	if calls != 5 {
		t.Fatalf("expected 5 calls (2 main + 3 settlement attempts), got %d", calls)
	}
	if writes.Facts != 1 {
		t.Fatalf("expected deterministic partial_progress fact write, got writes=%+v", writes)
	}
	factIDs, err := store.FactsYielded(iid)
	if err != nil || len(factIDs) != 1 {
		t.Fatalf("expected 1 yielded partial_progress fact, got ids=%v err=%v", factIDs, err)
	}
	fn, err := store.GetNode(factIDs[0])
	if err != nil || fn == nil {
		t.Fatalf("GetNode fallback fact: %v", err)
	}
	if !strings.Contains(string(fn.Payload), "partial_progress") || !strings.Contains(string(fn.Payload), "observed-port-8080-open") {
		t.Fatalf("fallback fact missing partial_progress or observed tool output: %s", fn.Payload)
	}
}
