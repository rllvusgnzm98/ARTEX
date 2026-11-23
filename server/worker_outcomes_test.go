package server

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
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
	for _, mode := range []string{"denied", "cancelled"} {
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
			calls := 0
			provider := retestProvider{complete: func(ctx context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
				calls++
				path := fixture
				if calls > 2 {
					if mode == "cancelled" {
						cancel()
						return llm.Message{}, "", llm.Usage{}, ctx.Err()
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
			if _, err := os.Stat(fixture); err != nil {
				t.Fatalf("trigger fixture was not executed: %v", err)
			}
			if _, err := os.Stat(blocked); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("post-latch operation was not blocked: %v", err)
			}

			rows, _, err := store.ActivityList(&iid, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			wantClass, wantCalls := "stop_loss", 5
			if mode == "cancelled" {
				wantClass, wantCalls = "cancelled", 3
			}
			terminations := 0
			for _, a := range rows {
				if a.Kind != "termination" {
					continue
				}
				terminations++
				var terminal struct {
					Class string `json:"outcome_class"`
					RunID string `json:"run_id"`
					Kind  string `json:"stop_loss_kind"`
				}
				if err := json.Unmarshal(a.Metadata, &terminal); err != nil || terminal.Class != wantClass || terminal.RunID == "" || terminal.Kind != "repeated_command" {
					t.Fatalf("termination metadata = %s, error = %v", a.Metadata, err)
				}
			}
			if terminations != 1 || calls != wantCalls {
				t.Fatalf("persisted terminations=%d, calls=%d; want 1 termination and %d calls", terminations, calls, wantCalls)
			}
		})
	}
}
