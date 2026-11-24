package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

func TestSanitizeTranscriptTailForWAF(t *testing.T) {
	dir := t.TempDir()
	store := transcript.NewStore(dir)
	sessID := "exp8-work-848"
	path := store.MainPath(sessID)

	// Earlier benign turn should stay untouched; tail turn with React2Shell / CVE-2025-55182
	// should be redacted while preserving JSONL transcript structure and idempotency.
	benignIn := json.RawMessage(`{"command":"curl -s http://10.0.0.1/"}`)
	wafIn := json.RawMessage(`{"command":"cat /root/nuclei-templates/http/cves/2025/CVE-2025-55182.yaml"}`)
	wafResult := "id: CVE-2025-55182\nNext-Action: React2Shell __proto__ $@flight payload " + strings.Repeat("x", 160)

	recs := []transcript.Record{
		{
			UUID: "u1", SessionID: sessID, Timestamp: "2026-11-24T00:00:00Z", Type: "message",
			Message: &llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.TextBlock("start intent")}},
		},
		{
			UUID: "u2", ParentUUID: "u1", SessionID: sessID, Timestamp: "2026-11-24T00:00:01Z", Type: "message",
			Message: &llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
				{Type: llm.BlockToolUse, ID: "tu1", Name: "Bash", Input: benignIn},
			}},
		},
		{
			UUID: "u3", ParentUUID: "u2", SessionID: sessID, Timestamp: "2026-11-24T00:00:02Z", Type: "message",
			Message: &llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{
				llm.ToolResultText("tu1", "200 OK", false),
			}},
		},
		{
			UUID: "u4", ParentUUID: "u3", SessionID: sessID, Timestamp: "2026-11-24T00:00:03Z", Type: "message",
			Message: &llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
				{Type: llm.BlockToolUse, ID: "tu2", Name: "Bash", Input: wafIn},
			}},
		},
		{
			UUID: "u5", ParentUUID: "u4", SessionID: sessID, Timestamp: "2026-11-24T00:00:04Z", Type: "message",
			Message: &llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{
				llm.ToolResultText("tu2", wafResult, false),
			}},
		},
	}
	if err := store.Append(path, recs...); err != nil {
		t.Fatal(err)
	}

	scrubbed, err := SanitizeTranscriptTailForWAF(store, sessID)
	if err != nil || !scrubbed {
		t.Fatalf("first SanitizeTranscriptTailForWAF = (%v, %v), want (true, nil)", scrubbed, err)
	}

	loaded, err := store.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != len(recs) {
		t.Fatalf("loaded records len=%d, want %d", len(loaded), len(recs))
	}
	if got := string(loaded[1].Message.Content[0].Input); got != string(benignIn) {
		t.Fatalf("earlier benign tool_use mutated: %s", got)
	}
	if got := blocksText(loaded[2].Message.Content[0].Content); got != "200 OK" {
		t.Fatalf("earlier benign tool_result mutated: %s", got)
	}
	if got := string(loaded[3].Message.Content[0].Input); !strings.Contains(got, "[WAF-SANITIZED:") || strings.Contains(got, "CVE-2025-55182") {
		t.Fatalf("tail waf tool_use not redacted cleanly: %s", got)
	}
	if got := blocksText(loaded[4].Message.Content[0].Content); !strings.Contains(got, "[WAF-SANITIZED:") || strings.Contains(got, "React2Shell") {
		t.Fatalf("tail waf tool_result not redacted cleanly: %s", got)
	}

	// Second call must be idempotent so we never loop endlessly on persistent blocks.
	scrubbed2, err := SanitizeTranscriptTailForWAF(store, sessID)
	if err != nil || scrubbed2 {
		t.Fatalf("second SanitizeTranscriptTailForWAF = (%v, %v), want (false, nil)", scrubbed2, err)
	}
}
