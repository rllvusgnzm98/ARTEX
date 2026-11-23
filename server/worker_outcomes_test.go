package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
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
		{harness.ReasonModelError, &agent.CallTimeoutError{Provider: "openai", Model: "m", Timeout: time.Second, Elapsed: time.Second}, agent.StopLossVerdict{}, agent.WriteCounts{}, "llm_timeout", "call_timeout"},
		{harness.ReasonModelError, &agent.StreamIdleTimeoutError{Idle: time.Second}, agent.StopLossVerdict{}, agent.WriteCounts{}, "llm_timeout", "call_timeout"},
		{harness.ReasonModelError, errors.New("status 402: insufficient_quota"), agent.StopLossVerdict{}, agent.WriteCounts{}, "supply_failure", "http_402"},
		{harness.ReasonModelError, errors.New("insufficient_quota"), agent.StopLossVerdict{}, agent.WriteCounts{}, "supply_failure", "quota_exhausted"},
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

func TestEnginePostStopLossRecordsOneTermination(t *testing.T) {
	repeatLimit := agent.DefaultStopLossPolicy().RepeatCommandLimit
	for _, mode := range []string{"denied", "cancelled", "link_timeout", "retry_writes"} {
		t.Run(mode, func(t *testing.T) {
			pg := openTestPG(t)
			row, err := pg.CreateTask("stop-loss fixture", "", nil, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := pg.DeleteTask(row.ID); err != nil {
					t.Error(err)
				}
			})
			store := pg.Exploration(row.ExplorationID)
			if mode == "link_timeout" || mode == "retry_writes" {
				dsn, _, err := db.DSN()
				if err != nil {
					t.Fatal(err)
				}
				if parsed, err := url.Parse(dsn); err == nil && parsed.Scheme != "" {
					q := parsed.Query()
					q.Set("lock_timeout", "300ms")
					parsed.RawQuery = q.Encode()
					dsn = parsed.String()
				} else {
					dsn += " lock_timeout=300ms"
				}
				writer, err := db.Open(dsn)
				if err != nil {
					t.Fatal(err)
				}
				defer writer.Close()
				store = writer.Exploration(row.ExplorationID)
			}
			iid, err := store.AddIntent(map[string]any{"summary": "local fixture"}, 0, nil, "test")
			if err != nil {
				t.Fatal(err)
			}
			if err := store.SetIntentState(iid, "running"); err != nil {
				t.Fatal(err)
			}
			intent, err := store.GetNode(iid)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			dir := t.TempDir()
			fixture, blocked := filepath.Join(dir, "fixture.txt"), filepath.Join(dir, "blocked.txt")
			lock, err := pg.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Rollback()
			if mode == "link_timeout" {
				if _, err := lock.Exec("LOCK TABLE exploration_edges IN EXCLUSIVE MODE"); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			provider := retestProvider{complete: func(ctx context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
				calls++
				if mode == "retry_writes" {
					switch calls {
					case 1, 2, 4:
						if calls == 2 {
							if _, err := lock.ExecContext(ctx, "LOCK TABLE exploration_edges IN EXCLUSIVE MODE"); err != nil {
								t.Errorf("lock exploration_edges: %v", err)
								return llm.Message{}, "", llm.Usage{}, err
							}
						}
						input, _ := json.Marshal(map[string]any{"summary": "checkpoint", "intent_id": iid})
						return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
							{Type: llm.BlockToolUse, ID: strconv.Itoa(calls), Name: "record_fact", Input: input},
						}}, "tool_use", llm.Usage{}, nil
					case 3:
						if err := lock.Rollback(); err != nil {
							t.Errorf("unlock exploration_edges: %v", err)
						}
						return llm.Message{}, "", llm.Usage{}, errors.New("fixture transient model failure")
					default:
						return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("done")}}, "end_turn", llm.Usage{}, nil
					}
				}
				path := fixture
				if calls > repeatLimit {
					if mode == "cancelled" {
						cancel()
						return llm.Message{}, "", llm.Usage{}, ctx.Err()
					}
					if mode == "link_timeout" {
						if calls > repeatLimit+1 {
							return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("done")}}, "end_turn", llm.Usage{}, nil
						}
						input, _ := json.Marshal(map[string]any{"summary": "checkpoint", "intent_id": iid})
						return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
							{Type: llm.BlockToolUse, ID: "fact", Name: "record_fact", Input: input},
						}}, "tool_use", llm.Usage{}, nil
					}
					path = blocked
				}
				input, _ := json.Marshal(map[string]string{"file_path": path, "content": "fixture"})
				return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
					{Type: llm.BlockToolUse, ID: strconv.Itoa(calls), Name: "Write", Input: input},
				}}, "tool_use", llm.Usage{}, nil
			}}
			worker := agent.NewWorker(provider, "test", dir, nil, 0, 0)
			worker.SetNonStreaming(func() bool { return true })
			worker.SetRunTimeout(5 * time.Second)
			task := &Task{ID: strconv.FormatInt(row.ID, 10), ExpID: row.ExplorationID, Guard: guard.New(), Store: store}
			engine := NewEngine(&Manager{})
			engine.runIntent(ctx, task, "test", worker, intent, "", "")
			if mode != "retry_writes" {
				if _, err := os.Stat(fixture); err != nil {
					t.Fatalf("trigger fixture was not executed: %v", err)
				}
			}
			if _, err := os.Stat(blocked); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("post-latch operation was not blocked: %v", err)
			}

			rows, _, err := store.ActivityList(&iid, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			wantClass, wantCalls := "stop_loss", repeatLimit+3
			wantKind := "repeated_command"
			wantWrites := agent.WriteCounts{}
			if mode == "cancelled" {
				wantClass, wantCalls = "cancelled", repeatLimit+1
			}
			if mode == "link_timeout" {
				wantClass, wantCalls = "persistence_failed", repeatLimit+2
				wantWrites.Failures = 1
				triggers := task.drainTriggers()
				if len(triggers) != 1 || triggers[0].Kind != "done" || triggers[0].IntentID != iid {
					t.Fatalf("NotifyDone triggers=%+v", triggers)
				}
			}
			if mode == "retry_writes" {
				wantClass, wantKind = "persistence_failed", ""
				wantCalls = 5
				wantWrites = agent.WriteCounts{Facts: 2, Failures: 1}
			}
			terminations := 0
			toolOutcomes := 0
			var audit db.Activity
			for _, a := range rows {
				if a.Kind == "tool_result" && strings.Contains(string(a.Metadata), "policy_blocked") {
					if a.IsError {
						t.Fatal("stored policy denial is an error")
					}
					toolOutcomes++
				}
				if mode == "link_timeout" && a.Kind == "tool_result" && a.Tool == "record_fact" {
					if !a.IsError || !strings.Contains(string(a.Metadata), "tool_error") || !strings.Contains(a.Summary, "link fact to intent") || !strings.Contains(a.Summary, "55P03") {
						t.Fatalf("record_fact did not report the link timeout: %+v", a)
					}
					toolOutcomes++
				}
				if a.Kind != "termination" {
					continue
				}
				audit = a
				terminations++
				var terminal struct {
					Class  string            `json:"outcome_class"`
					RunID  string            `json:"run_id"`
					Kind   string            `json:"stop_loss_kind"`
					Writes agent.WriteCounts `json:"evidence_counts"`
				}
				if err := json.Unmarshal(a.Metadata, &terminal); err != nil || terminal.Class != wantClass || terminal.RunID == "" || terminal.Kind != wantKind || terminal.Writes != wantWrites {
					t.Fatalf("termination metadata = %s, error = %v", a.Metadata, err)
				}
			}
			if terminations != 1 || calls != wantCalls {
				t.Fatalf("persisted terminations=%d, calls=%d; want 1 termination and %d calls", terminations, calls, wantCalls)
			}
			if mode == "denied" && toolOutcomes != 3 || mode == "link_timeout" && toolOutcomes != 1 {
				t.Fatalf("persisted tool outcomes=%d", toolOutcomes)
			}
			if mode == "cancelled" {
				if _, err := store.CancelIntent(iid); err != nil {
					t.Fatal(err)
				}
				if id, err := store.AppendActivity(audit); err != nil || id != audit.ID {
					t.Fatalf("hard cancellation or retry lost the original audit record: got id=%d err=%v want id=%d", id, err, audit.ID)
				}
			}
		})
	}
}

func TestConcurrentHardCancelRetainsPendingTermination(t *testing.T) {
	pg := openTestPG(t)
	row, err := pg.CreateTask("hard cancel audit fixture", "", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pg.DeleteTask(row.ID); err != nil {
			t.Error(err)
		}
	})
	store := pg.Exploration(row.ExplorationID)
	iid, err := store.AddIntent(map[string]any{"summary": "cancelled fixture"}, 0, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentState(iid, "running"); err != nil {
		t.Fatal(err)
	}
	task := &Task{ID: strconv.FormatInt(row.ID, 10), ExpID: row.ExplorationID, Store: store}
	server := &Server{engine: NewEngine(&Manager{pg: pg})}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	workCtx, stopWork := context.WithCancelCause(ctx)
	defer stopWork(nil)
	server.engine.registerWork(iid, stopWork)

	firstCancel := make(chan error, 1)
	go func() {
		_, err := server.applyIntentControl(ctx, task, iid, "cancel", "first request", "hard")
		firstCancel <- err
	}()
	select {
	case <-workCtx.Done():
		if !errors.Is(context.Cause(workCtx), agent.AbortWorkCancelledByUser) {
			t.Fatalf("worker was not cancelled by the first request: %v", context.Cause(workCtx))
		}
	case err := <-firstCancel:
		t.Fatalf("first request returned before worker cancellation: %v", err)
	}
	action, complete := server.engine.detachWork(iid)
	if action != "cancel" {
		t.Fatalf("worker action = %q", action)
	}
	if err := transitionIntentState(store, iid, "running", "paused"); err != nil {
		t.Fatal(err)
	}
	out, err := server.applyIntentControl(ctx, task, iid, "cancel", "second request", "hard")
	if err != nil || out.Deleted == nil {
		t.Fatalf("second hard cancel did not delete the paused intent: %+v %v", out, err)
	}
	// Resume the worker at its deferred audit write, after the cleanup won.
	meta, err := json.Marshal(map[string]any{"run_id": "pending-audit", "intent_id": iid, "outcome_class": "cancelled"})
	if err != nil {
		t.Fatal(err)
	}
	activity := server.engine.emitActivity(task, db.Activity{Kind: "termination", NodeID: &iid, Metadata: meta})
	complete(nil)
	select {
	case err := <-firstCancel:
		if err == nil || !strings.Contains(err.Error(), "intent not found") {
			t.Fatalf("first request should find cleanup already completed: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("first request did not finish")
	}
	var rows, nullNodes int
	if err := pg.QueryRow(`SELECT count(*), count(*) FILTER (WHERE node_id IS NULL)
FROM activity WHERE exploration_id=$1 AND kind='termination' AND metadata->>'run_id'='pending-audit'
  AND (metadata->>'intent_id')::bigint=$2`, task.ExpID, iid).Scan(&rows, &nullNodes); err != nil {
		t.Fatal(err)
	}
	if activity.ID == 0 || rows != 1 || nullNodes != 1 {
		t.Fatalf("termination activity id=%d rows=%d detached=%d", activity.ID, rows, nullNodes)
	}
}
