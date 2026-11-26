package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/harness"
)

func TestPlannerAddIntentRejectsBroadSweepAllowsAtomic(t *testing.T) {
	_, store := retentionStore(t)
	plannerTools := NewToolSet(store, "planner")
	// Default (detached): planner is not blocked by broad-sweep keyword guard.
	if id, err := plannerTools.addOneIntentCtx(context.Background(), intentItem{
		Summary: "对账兜底收割未被覆盖题：先 GET challenges 再依次解题",
	}); err != nil || id <= 0 {
		t.Fatalf("default detached planner add_intent should succeed, got id=%d err=%v", id, err)
	}

	// Opt-in guard enabled: omnibus sweep intents are rejected while atomic intents pass.
	t.Setenv("ARTEX_ENABLE_PLANNER_ATOMIC_GUARD", "1")
	if _, err := plannerTools.addOneIntentCtx(context.Background(), intentItem{
		Summary: "对账兜底收割未被覆盖题：先 GET challenges 再依次解题",
	}); err == nil || !strings.Contains(err.Error(), "1 意图 = 1 个明确目标") {
		t.Fatalf("planner omnibus sweep intent must be rejected when guard enabled, got err=%v", err)
	}
	if _, err := plannerTools.addOneIntentCtx(context.Background(), intentItem{
		Summary: "从 hard 难度题切入高分区，自动挑题拿分",
	}); err == nil {
		t.Fatal("planner difficulty sweep intent must be rejected when guard enabled")
	}
	if _, err := plannerTools.addOneIntentCtx(context.Background(), intentItem{
		Summary: "TSecBench 滚动补位线（占未来空出的容器位）",
	}); err == nil {
		t.Fatal("planner rolling slot-filler sweep intent must be rejected when guard enabled")
	}

	// Single atomic target passes for planner.
	id, err := plannerTools.addOneIntentCtx(context.Background(), intentItem{
		Summary: "续解 b-02（http://10.0.164.136:80）：利用 SQL 注入写 webshell 验证内网横向路径",
	});
	if err != nil || id <= 0 {
		t.Fatalf("atomic planner intent failed: id=%d err=%v", id, err)
	}

	// Human/MainAgent orchestrator retains direct add_intent capability.
	humanTools := NewToolSet(store, "human")
	if _, err := humanTools.addOneIntentCtx(context.Background(), intentItem{
		Summary: "立即核对 b-03（http://10.0.164.138:80）内网 flag",
	}); err != nil {
		t.Fatalf("human add_intent failed: %v", err)
	}
}

func TestCompactIntentsIncludesBlockedReasonAndWAFReasonText(t *testing.T) {
	nodes := []*db.Node{{
		ID:            42,
		Kind:          db.KindIntent,
		State:         "blocked",
		BlockedReason: db.IntentBlockedGatewayWAF,
		Payload:       []byte(`{"summary":"test c-03"}`),
	}}
	out := compactIntents(nodes, nil, nil)
	if len(out) != 1 || out[0]["blocked_reason"] != db.IntentBlockedGatewayWAF {
		t.Fatalf("compactIntents dropped blocked_reason: %+v", out)
	}

	sum, detail := terminalText(context.Background(), &harness.Terminal{
		Reason: harness.ReasonModelError,
		Err:    errors.New("openai: status 403: <!DOCTYPE html><title>Attention Required! | Cloudflare</title>"),
	}, &runTrace{})
	if !strings.Contains(sum, "gateway_waf_blocked") || !strings.Contains(detail, "Cloudflare WAF") {
		t.Fatalf("terminalText must surface gateway_waf_blocked, got sum=%q detail=%q", sum, detail)
	}
}

func TestAddIntentSchemaExposesItemPropsAndRejectsNestedOrPlaceholder(t *testing.T) {
	_, store := retentionStore(t)
	ts := NewToolSet(store, "planner")
	tool := ts.addIntent()
	props, _ := tool.InputSchema()["properties"].(map[string]any)
	intentsSchema, _ := props["intents"].(map[string]any)
	itemsSchema, _ := intentsSchema["items"].(map[string]any)
	itemProps, _ := itemsSchema["properties"].(map[string]any)
	for _, wantKey := range []string{"summary", "asset_ids", "parent_ids", "priority", "chain_tags"} {
		if _, ok := itemProps[wantKey]; !ok {
			t.Fatalf("add_intent intents.items.properties missing %q: %+v", wantKey, itemProps)
		}
	}

	nestedRaw := json.RawMessage(`{"intents":[{"summary":"批量派单","intents":[{"summary":"针对 192.168.52.30 打内网纵深"}]}]}`)
	res, err := tool.Call(t.Context(), nestedRaw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Flatten(), "禁止再次嵌套") {
		t.Fatalf("double-nested intents must be rejected cleanly, got: %s", res.Flatten())
	}
	if n, err := store.CountByKind(db.KindIntent); err != nil || n != 0 {
		t.Fatalf("nested shell intent leaked into DB: count=%d err=%v", n, err)
	}

	placeholderRaw := json.RawMessage(`{"intents":[{"summary":"批量派单"}]}`)
	res2, err := tool.Call(t.Context(), placeholderRaw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res2.Flatten(), "疑似包装标题") {
		t.Fatalf("placeholder summary must be rejected cleanly, got: %s", res2.Flatten())
	}
}
