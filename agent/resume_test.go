package agent

import (
	"bytes"
	"context"
	"fmt"
	"iter"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

type resumeProvider struct {
	requests []llm.CompletionRequest
}

func (p *resumeProvider) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.requests = append(p.requests, req)
	return assistantText("fresh continuation"), "end_turn", llm.Usage{}, nil
}

func (p *resumeProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	panic("test must use non-streaming provider")
}

type resumeLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *resumeLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *resumeLog) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestResumeHistoryRunners(t *testing.T) {
	for _, runner := range []string{"worker", "mainagent", "chat"} {
		for _, history := range []string{"corrupt", "missing", "valid"} {
			t.Run(runner+"/"+history, func(t *testing.T) {
				d, ts := retentionStore(t)
				var taskID int64
				if err := d.QueryRow(`SELECT id FROM tasks WHERE exploration_id=$1`, ts.ID()).Scan(&taskID); err != nil {
					t.Fatal(err)
				}
				intentID, err := ts.AddIntent(map[string]any{"summary": "resume test"}, 0, nil, "planner")
				if err != nil {
					t.Fatal(err)
				}
				intent, err := ts.GetNode(intentID)
				if err != nil {
					t.Fatal(err)
				}
				sessionID := "conv-restore-test"
				if runner == "worker" {
					sessionID = WorkerSessionID(ts.ID(), intentID)
				} else if runner == "mainagent" {
					sessionID = fmt.Sprintf("exp%d-main", ts.ID())
				}
				store := transcript.NewStore(t.TempDir())
				switch history {
				case "corrupt":
					if err := os.WriteFile(store.MainPath(sessionID), []byte("{broken transcript\n"), 0600); err != nil {
						t.Fatal(err)
					}
				case "valid":
					prior := llm.UserText("PRIOR_CONTEXT_SENTINEL")
					if err := store.Append(store.MainPath(sessionID), transcript.Record{UUID: "prior", SessionID: sessionID, Type: "message", Message: &prior}); err != nil {
						t.Fatal(err)
					}
				}
				logs := &resumeLog{}
				originalLog := log.Writer()
				log.SetOutput(logs)
				t.Cleanup(func() { log.SetOutput(originalLog) })
				provider := &resumeProvider{}
				var activities []db.Activity
				emit := func(a db.Activity) { activities = append(activities, a) }
				const input = "continue the current request"
				workDir := t.TempDir()
				switch runner {
				case "worker":
					worker := NewWorker(provider, "test", workDir, store, 128000, 3)
					worker.SetNonStreaming(func() bool { return true })
					_, _, err = worker.ExecuteWithMessage(t.Context(), "work-restore", taskID, nil, ts, intent, nil, emit, nil, nil, "request-test", input)
				case "mainagent":
					main := NewMainAgent(provider, "test", workDir, store, 128000, 3)
					main.SetNonStreaming(func() bool { return true })
					_, err = main.Chat(t.Context(), taskID, 0, nil, ts, "restore context", input, emit, nil, nil, nil, nil)
				case "chat":
					chat := NewChatAgent(provider, "test", workDir, store, 128000)
					chat.SetNonStreaming(func() bool { return true })
					_, err = chat.Chat(t.Context(), "test-chat", sessionID, input, 3, time.Minute, false, emit)
				}
				if err != nil {
					t.Fatalf("runner must continue: %v", err)
				}
				if len(provider.requests) != 1 {
					t.Fatalf("provider requests=%d want 1", len(provider.requests))
				}
				var text strings.Builder
				for _, message := range provider.requests[0].Messages {
					for _, block := range message.Content {
						text.WriteString(block.Text)
					}
				}
				got := text.String()
				if !strings.Contains(got, input) {
					t.Fatalf("current input lost: %q", got)
				}
				var restoreErrors []db.Activity
				for _, a := range activities {
					if a.Kind == "error" && strings.Contains(a.Detail, "history restoration failed:") {
						restoreErrors = append(restoreErrors, a)
					}
				}
				if history == "corrupt" {
					warningAt := strings.Index(got, "history restoration failed: transcript: corrupt line:")
					if warningAt < 0 || warningAt > strings.Index(got, input) || !strings.Contains(got, "; previous context lost, re-read graph/transcript") {
						t.Errorf("missing model warning: %q", got)
					}
					if len(restoreErrors) != 1 || !restoreErrors[0].IsError || restoreErrors[0].Worker == "" {
						t.Fatalf("missing error activity: %+v", restoreErrors)
					}
					if !strings.Contains(logs.String(), "[resume] session="+sessionID) {
						t.Errorf("missing session id in logs: %s", logs.String())
					}
					if runner == "worker" {
						if restoreErrors[0].NodeID == nil || *restoreErrors[0].NodeID != intentID {
							t.Errorf("error activity lost intent id: %+v", restoreErrors[0])
						}
						hints, _ := NewToolSet(ts, "planner").graphOverviewData()["hints"].([]map[string]any)
						if len(hints) != 1 || !strings.Contains(fmt.Sprint(hints[0]["text"]), sessionID) || !strings.Contains(fmt.Sprint(hints[0]["text"]), "history restoration failed:") {
							t.Errorf("worker warning not visible to planner: %v", hints)
						}
					}
				} else {
					if len(restoreErrors) != 0 || strings.Contains(got, "history restoration failed:") || strings.Contains(logs.String(), "[resume]") {
						t.Errorf("unexpected restoration warning: %q, %+v, %s", got, restoreErrors, logs.String())
					}
					if history == "valid" && !strings.Contains(got, "PRIOR_CONTEXT_SENTINEL") {
						t.Error("valid prior history lost")
					}
				}
			})
		}
	}
}

func TestResumeHistoryWithoutEmitter(t *testing.T) {
	s := agentcore.NewSession(agentcore.Options{})
	t.Cleanup(func() { _ = s.Close() })
	if warning := resumeHistory(s, "no-transcript", "test", nil); !strings.HasPrefix(warning, "history restoration failed:") {
		t.Fatalf("missing warning without emitter: %q", warning)
	}
}
