package agent

import (
	"context"
	"strings"
	"testing"
)

func TestMainAgentFenceBlocksTargetActionsAllowsLocalReadsAndCommandTools(t *testing.T) {
	h := WrapMainAgentFence(nil)

	blocked := []struct {
		name  string
		tool  string
		input string
	}{
		{"curl target", "Bash", `{"command":"curl http://192.168.111.79/php-cgi/php-cgi.exe"}`},
		{"upload/write file", "Bash", `{"command":"cat > /tmp/exp.py <<'EOF'\nprint(1)\nEOF"}`},
		{"python socket exploit", "Bash", `{"command":"python3 -c \"import socket; socket.create_connection(('192.168.111.79', 80))\""}`},
		{"webfetch", "WebFetch", `{"url":"http://192.168.111.79/"}`},
		{"mcp tool", "mcp__browser__open", `{"url":"http://192.168.111.79/"}`},
		{"malformed bash json", "Bash", `not-json`},
	}
	for _, tc := range blocked {
		block, msg, _ := h.PreToolUse(context.Background(), tc.tool, []byte(tc.input))
		if !block || !strings.Contains(msg, MainAgentFenceMessagePrefix) {
			t.Fatalf("%s must be blocked by MainAgent fence, block=%v msg=%q", tc.name, block, msg)
		}
		if !strings.Contains(msg, "add_intent") {
			t.Fatalf("%s block message must redirect to add_intent, got %q", tc.name, msg)
		}
	}

	allowed := []struct {
		name  string
		tool  string
		input string
	}{
		{"ls wordlists", "Bash", `{"command":"ls /Users/demo/wordlists/seclists/ 2>/dev/null | head -30"}`},
		{"cat death manifest", "Bash", `{"command":"cat shared/death_manifest_i10815.json 2>/dev/null; echo \"---TAIL---\"; cat shared/bg_i10815_0_task_25_tail.txt 2>/dev/null"}`},
		{"offline base64 decode", "Bash", `{"command":"cd shared && sed -n '/^==B64==$/,/^==========*$/p' loot.txt | grep -v '^==' | tr -d '[:space:]' | base64 -D 2>/dev/null | iconv -f GB18030 -t UTF-8 2>/dev/null | tail -50"}`},
		{"Read tool", "Read", `{"file_path":"shared/loot.txt"}`},
		{"LS tool", "LS", `{"path":"/data/wordlists"}`},
		{"add_hint", "add_hint", `{"text":"wordlists path"}`},
		{"add_intent", "add_intent", `{"summary":"probe target"}`},
		{"steer_work", "steer_work", `{"intent_id":1,"message":"focus"}`},
		{"kill_work", "kill_work", `{"intent_id":1}`},
		{"node_detail", "node_detail", `{"ids":[1,2,3]}`},
	}
	for _, tc := range allowed {
		if block, msg, _ := h.PreToolUse(context.Background(), tc.tool, []byte(tc.input)); block {
			t.Fatalf("%s must be allowed on command seat, got block=%q", tc.name, msg)
		}
	}

	inner := &stubInnerGuard{block: true, msg: "inner guard"}
	wrapped := WrapMainAgentFence(inner)
	if block, msg, _ := wrapped.PreToolUse(context.Background(), "Read", []byte(`{}`)); !block || msg != "inner guard" || inner.called != 1 {
		t.Fatalf("allowed tool must delegate to inner guard, block=%v msg=%q called=%d", block, msg, inner.called)
	}
}

func TestMainAgentSystemIncludesCommandSeatRedline(t *testing.T) {
	t.Cleanup(func() { PromptOverride = nil })
	PromptOverride = func(string) (string, bool) { return "custom editable body", true }
	sys := mainAgentSystem("get flag", "/data", "/data/tasks/1")
	if !strings.Contains(sys, "指挥席红线（不可编辑）") || !strings.Contains(sys, "严禁亲自通过 Bash") {
		t.Fatalf("code-owned command seat rules must survive PromptOverride:\n%s", sys)
	}
}
