package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/compaction"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

func appendRetentionTranscript(t *testing.T, store *transcript.Store, session string, msgs ...llm.Message) {
	t.Helper()
	for i, msg := range msgs {
		if err := store.Append(store.MainPath(session), transcript.Record{UUID: fmt.Sprint(i), SessionID: session, Type: "message", Message: &msg}); err != nil {
			t.Fatal(err)
		}
	}
}

func microHistory(first string) []llm.Message {
	var msgs []llm.Message
	for i := range 7 {
		id := fmt.Sprintf("tool-%d", i)
		text := strings.Repeat("result ", 20)
		if i == 0 {
			text = first
		}
		msgs = append(msgs,
			llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: id, Name: "Read", Input: json.RawMessage(`{"file_path":"fixture"}`)}}},
			llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{{Type: llm.BlockToolResult, ToolUseID: id, Content: []llm.ContentBlock{llm.TextBlock(text)}}}},
		)
	}
	return msgs
}

func TestRecoverableMicroCompaction(t *testing.T) {
	for _, mode := range []string{"spill", "transcript", "none", "missing_transcript", "legacy_spill"} {
		t.Run(mode, func(t *testing.T) {
			store := transcript.NewStore(t.TempDir())
			opts := agentcore.Options{Compaction: compactionConfig(100000), Transcript: store, SessionID: "micro"}
			original := "original observation"
			var spill string
			if mode == "spill" {
				dir := t.TempDir()
				wrapped := &outputSpillTool{CoreTool: outputProbe(nil)}
				original = wrapped.capture(&actool.ToolContext{WorkingDir: dir, OutputDir: cmdOutDir(dir)}, strings.Repeat("full evidence ", 4000))
				spill = spillReference(t, original)
			} else if mode == "legacy_spill" {
				spill = "cmd-output/legacy-output.txt"
				original = "head ... <persisted-output>[Output too large: full 40000 bytes / 2 lines.Full output saved to  " + spill + " </persisted-output>"
			}
			msgs := microHistory(original)
			if mode == "none" {
				opts.Transcript = nil
			} else if mode != "missing_transcript" {
				appendRetentionTranscript(t, store, "micro", msgs...)
			}
			installRuntimeCompactor(&opts, nil)
			if opts.Compaction != nil {
				t.Fatal("SDK Compaction must be disabled")
			}
			c := opts.Compactor.(*recoverableCompactor)
			stored := c.Pre(t.Context(), msgs, 60000)
			if !isClearedResult(stored[1].Content[0].Content) {
				t.Fatal("stored placeholder must retain exact SDK equality")
			}
			view := c.View(t.Context(), stored)
			text := view[1].Content[0].Content[0].Text
			if !strings.Contains(text, `tool="Read"`) || !strings.Contains(text, `tool_use_id="tool-0"`) {
				t.Errorf("missing tool identity: %s", text)
			}
			switch mode {
			case "spill", "legacy_spill":
				if !strings.Contains(text, spill) {
					t.Errorf("spill recovery path lost: %s", text)
				}
			case "transcript":
				if !strings.Contains(text, `recall_tool_result({"tool_use_id":"tool-0"})`) {
					t.Errorf("recall hint lost: %s", text)
				}
			default:
				if !strings.Contains(text, "No transcript exists for this session") || strings.Contains(text, "recall_tool_result(") {
					t.Errorf("must not advertise unavailable recall: %s", text)
				}
			}
			if !isClearedResult(stored[1].Content[0].Content) || !reflect.DeepEqual(view, c.View(t.Context(), stored)) {
				t.Fatal("ContextView mutated stored history or is not pure")
			}
			if second := c.Pre(t.Context(), stored, 60000); !isClearedResult(second[1].Content[0].Content) {
				t.Fatal("repeat compaction corrupted placeholders")
			}
		})
	}
}

func TestRecallToolResult(t *testing.T) {
	store := transcript.NewStore(t.TempDir())
	msgs := microHistory("original observed content")
	msgs[1].Content[0].IsError = true
	appendRetentionTranscript(t, store, "own", msgs...)
	cleared := msgs[1]
	cleared.Content = append([]llm.ContentBlock(nil), cleared.Content...)
	cleared.Content[0].Content = []llm.ContentBlock{llm.TextBlock(clearedToolResult)}
	appendRetentionTranscript(t, store, "own", cleared)
	appendRetentionTranscript(t, store, "other", microHistory("OTHER_SESSION_SECRET")...)
	tool := recallToolResult(store, "own")
	got, err := tool.Call(t.Context(), json.RawMessage(`{"tool_use_id":"tool-0"}`), nil)
	if err != nil || !got.IsError || got.Flatten() != "original observed content" || !tool.IsReadOnly(nil) || !tool.IsConcurrencySafe(nil) {
		t.Fatalf("original content/flags lost: %+v %v", got, err)
	}
	for _, input := range []string{`{}`, `{`, `{"tool_use_id":"unknown"}`} {
		got, err := tool.Call(t.Context(), json.RawMessage(input), nil)
		if err != nil || !got.IsError {
			t.Fatalf("bad recall input accepted: %s %v", got.Flatten(), err)
		}
	}
	missing := recallToolResult(store, "missing")
	if got, _ := missing.Call(t.Context(), json.RawMessage(`{"tool_use_id":"tool-0"}`), nil); !got.IsError || strings.Contains(got.Flatten(), "observed content") {
		t.Fatal("recall must be confined to its session")
	}
	if err := os.WriteFile(store.MainPath("corrupt"), []byte("{bad\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, _ := recallToolResult(store, "corrupt").Call(t.Context(), json.RawMessage(`{"tool_use_id":"tool-0"}`), nil); !got.IsError || !strings.Contains(got.Flatten(), "Transcript recovery failed") {
		t.Fatal("corrupt transcripts must report failure")
	}

	large := strings.Repeat("archived evidence\n", 3000)
	appendRetentionTranscript(t, store, "large", microHistory(large)...)
	dir := t.TempDir()
	opts := agentcore.Options{Transcript: store, SessionID: "large"}
	installRuntimeCompactor(&opts, nil)
	attachToolOutputSpilling(&opts)
	var recall actool.CoreTool
	for _, tool := range opts.Tools {
		if tool.Name() == "recall_tool_result" {
			recall = tool
		}
	}
	if recall == nil {
		t.Fatal("session recall tool not installed")
	}
	got, err = recall.Call(t.Context(), json.RawMessage(`{"tool_use_id":"tool-0"}`), &actool.ToolContext{WorkingDir: dir, OutputDir: cmdOutDir(dir)})
	if err != nil {
		t.Fatal(err)
	}
	full, err := os.ReadFile(filepath.Join(dir, spillReference(t, got.Flatten())))
	if err != nil || string(full) != large {
		t.Fatalf("large recall must spill losslessly: %v", err)
	}
}

type structuredSummaryProbe struct {
	requests []llm.CompletionRequest
	failure  error
}

func (p *structuredSummaryProbe) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.requests = append(p.requests, req)
	return assistantText("## Findings\nsummary"), "end_turn", llm.Usage{}, p.failure
}

func (p *structuredSummaryProbe) Stream(_ context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		p.requests = append(p.requests, req)
		yield(llm.StreamEvent{Type: llm.SETextDelta, Text: "## Findings\nsummary"}, p.failure)
	}
}

func summaryHistory() []llm.Message {
	var msgs []llm.Message
	for i := range 20 {
		msgs = append(msgs, llm.UserText(fmt.Sprintf("record-%d %s", i, strings.Repeat("old conversation ", 200))))
	}
	return msgs
}

func graphBlockFrom(t *testing.T, msgs []llm.Message) string {
	t.Helper()
	for _, msg := range msgs {
		if strings.HasPrefix(msg.Text(), graphRetentionMarker) {
			return msg.Text()
		}
	}
	t.Fatal("DB-backed retention block missing after compaction")
	return ""
}

func TestStructuredSummaryPreservesGraph(t *testing.T) {
	_, store := retentionStore(t)
	keyID, err := NewToolSet(store, "worker").recordOneFact(factItem{Summary: "cleanup pending", Category: "cleanup_status", EvidenceIDs: []string{"evidence:cleanup"}, Confidence: "inferred"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	findingID, err := store.AddNode(db.KindFinding, map[string]any{"summary": "confirmed finding"}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, nonStreaming := range []bool{false, true} {
		t.Run(fmt.Sprintf("non_streaming=%v", nonStreaming), func(t *testing.T) {
			probe := &structuredSummaryProbe{}
			opts := agentcore.Options{Provider: probe, Compaction: &compaction.Config{ContextWindow: 128000, KeepRecent: 2}, NonStreaming: nonStreaming}
			installRuntimeCompactor(&opts, store)
			c := opts.Compactor.(*recoverableCompactor)
			out, changed := c.Reactive(t.Context(), summaryHistory())
			if !changed || len(probe.requests) != 1 || opts.Compaction != nil {
				t.Fatalf("forced summary did not run: changed=%v requests=%d", changed, len(probe.requests))
			}
			prompt := strings.Join(probe.requests[0].System, "\n")
			for _, section := range []string{"## Findings", "## Evidence IDs", "## Negative results", "## Scope limits", "## Cleanup status", "## Open tasks"} {
				if !strings.Contains(prompt, section) {
					t.Errorf("summary prompt missing %s", section)
				}
			}
			block := graphBlockFrom(t, c.View(t.Context(), out))
			if len(c.View(t.Context(), out)) != 4 {
				t.Fatal("custom compaction config must retain exactly two recent messages plus summary and graph block")
			}
			for _, want := range []string{fmt.Sprintf(`"id":%d,`, keyID), fmt.Sprintf(`"id":%d,`, findingID), `"category":"cleanup_status"`, `"evidence_ids":["evidence:cleanup"]`, `"confidence":"inferred"`, "Omitted: findings=0; key facts=0", "list_facts / list_findings"} {
				if !strings.Contains(block, want) {
					t.Errorf("retention missing %q:\n%s", want, block)
				}
			}
			if strings.Count(block, graphRetentionMarker) != 1 || len(block) > graphRetentionBytes {
				t.Fatal("retention block must be bounded and nonduplicated")
			}
			unchanged := c.Pre(t.Context(), out, 0)
			if len(unchanged) != len(out) {
				t.Fatal("no new summary must not inject another retention block")
			}
		})
	}
}

func TestRetainedGraphCapsEmptyAndError(t *testing.T) {
	d, store := retentionStore(t)
	if block := retainedGraphBlock(store); !strings.Contains(block, "Omitted: findings=0; key facts=0") {
		t.Fatalf("empty graph: %s", block)
	}
	var firstKey int64
	for i := range 45 {
		id, err := NewToolSet(store, "worker").recordOneFact(factItem{Summary: fmt.Sprint("key", i), Category: "scope_limit"}, 0)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			firstKey = id
		}
	}
	for i := range 43 {
		if _, err := store.AddNode(db.KindFinding, map[string]any{"summary": fmt.Sprint("finding", i)}, 5, "confirmed", "worker", nil); err != nil {
			t.Fatal(err)
		}
	}
	block := retainedGraphBlock(store)
	if !strings.Contains(block, "Omitted: findings=3; key facts=5") || !strings.Contains(block, fmt.Sprintf(`"id":%d,`, firstKey)) || len(block) > graphRetentionBytes {
		t.Fatalf("wrong caps/ordering: %s", block)
	}
	if _, err := store.AddNode(db.KindFact, map[string]any{"summary": "huge reference", "evidence_ids": []string{strings.Repeat("x", graphRetentionBytes*2)}}, 5, "confirmed", "worker", nil); err != nil {
		t.Fatal(err)
	}
	refs, _ := json.Marshal([]string{strings.Repeat("x", graphRetentionBytes*2)})
	if _, err := d.Exec(`UPDATE exploration_nodes SET payload=jsonb_set(payload,'{evidence_ids}',$1::jsonb) WHERE exploration_id=$2 AND id=$3`, string(refs), store.ID(), firstKey); err != nil {
		t.Fatal(err)
	}
	if block := retainedGraphBlock(store); len(block) > graphRetentionBytes || !strings.Contains(block, "key facts=6") || strings.Contains(block, fmt.Sprintf(`"id":%d,`, firstKey)) {
		t.Fatal("oversized rows must be omitted with an exact count")
	}
	failedDB := testDB(t)
	failedStore := failedDB.Exploration(store.ID())
	if err := failedDB.Close(); err != nil {
		t.Fatal(err)
	}
	if block := retainedGraphBlock(failedStore); !strings.Contains(block, "retention failed") || !strings.Contains(block, "list_facts / list_findings") {
		t.Fatalf("DB errors must provide recovery guidance: %s", block)
	}
}

func TestStructuredSummaryWithoutStoreAndFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		probe := &structuredSummaryProbe{}
		if fail {
			probe.failure = errors.New("summary unavailable")
		}
		opts := agentcore.Options{Provider: probe, NonStreaming: true, Compaction: compactionConfig(128000)}
		installRuntimeCompactor(&opts, nil)
		msgs := summaryHistory()
		out, changed := opts.Compactor.Reactive(t.Context(), msgs)
		if fail {
			if changed || !reflect.DeepEqual(out, msgs) {
				t.Fatal("failed summary must leave history intact")
			}
		} else if !changed || llm.LastBoundaryIndex(out) < 0 {
			t.Fatal("chat still needs summarization without an exploration store")
		}
		for _, msg := range out {
			if strings.Contains(msg.Text(), graphRetentionMarker) {
				t.Fatal("no exploration store must not inject graph data")
			}
		}
	}
}

func TestRuntimeCompactorNoaOverride(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			opts := agentcore.Options{Compaction: compactionConfig(128000)}
			installRuntimeCompactor(&opts, nil)
			original := opts.Compactor
			session := enableNoa(&opts, func() bool { return enabled }, t.TempDir(), "runtime-noa", 128000, func(msg string) { t.Error(msg) })
			if opts.Compaction != nil {
				t.Fatal("Compaction must remain nil")
			}
			if enabled {
				if session == nil || session.Config().ModelContextLimit != 128000 || opts.Compactor == original {
					t.Fatal("noa must replace the wrapper with the real window")
				}
			} else if session != nil || opts.Compactor != original {
				t.Fatal("default wrapper must remain installed when noa is disabled")
			}
		})
	}
}
