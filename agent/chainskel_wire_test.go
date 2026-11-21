package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent/chainskel"
)

// ForIntent 骨架注入接到了 worker 系统提示装配(execute 中 renderIntentTask 之后)。
func TestChainskelForIntentWired(t *testing.T) {
	payload := json.RawMessage(`{"summary":"test sqli on login form","chain_tags":["web"]}`)
	got := chainskel.ForIntent(payload)
	if got == "" || !strings.Contains(got, "<chains-skeleton") {
		t.Fatalf("expected a chains-skeleton block for web tag, got %q", got)
	}
}

// meta 铁律接到了 planner / worker 的代码固定尾。
func TestChainskelMetaRulesWired(t *testing.T) {
	ps := plannerSystem("goal", "/data", "/work")
	if !strings.Contains(ps, "meta 铁律(反问纪律,全程在场)") {
		t.Fatalf("plannerSystem missing PlannerMetaRules tail")
	}
	ws := workerSystem("", "", "/data", "/run", false, DefaultFootprint())
	if !strings.Contains(ws, "meta 铁律(观测真伪与卡住自检)") {
		t.Fatalf("workerSystem missing WorkerMetaRules tail")
	}
}
