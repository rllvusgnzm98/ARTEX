package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/harness"
)

func TestPlannerAddIntentRejectsBroadSweepAllowsAtomic(t *testing.T) {
	_, store := retentionStore(t)
	plannerTools := NewToolSet(store, "planner")
	if _, err := plannerTools.addOneIntentCtx(context.Background(), intentItem{
		Summary: "对账兜底收割未被覆盖题：先 GET challenges 再依次解题",
	}); err == nil || !strings.Contains(err.Error(), "1 意图 = 1 个明确目标") {
		t.Fatalf("planner omnibus sweep intent must be rejected, got err=%v", err)
	}
	if _, err := plannerTools.addOneIntentCtx(context.Background(), intentItem{
		Summary: "从 hard 难度题切入高分区，自动挑题拿分",
	}); err == nil {
		t.Fatal("planner difficulty sweep intent must be rejected")
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
