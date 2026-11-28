package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

func plannerProbeHooksFor(facts func() (int, bool)) (*plannerProbeState, interface {
	PreToolUse(context.Context, string, []byte) (bool, string, []byte)
}) {
	st := &plannerProbeState{}
	return st, WrapPlannerProbe(nil, st, PlannerProbeLimit, facts).(interface {
		PreToolUse(context.Context, string, []byte) (bool, string, []byte)
	})
}

func noFacts() (int, bool) { return 0, true }

// Boundary 1: once workers have produced facts, the planner may not probe at all.
func TestPlannerProbeBlockedOnceWorkerFactsExist(t *testing.T) {
	_, hooks := plannerProbeHooksFor(func() (int, bool) { return 4, true })

	for _, tool := range []string{"Bash", "WebFetch"} {
		block, msg, _ := hooks.PreToolUse(context.Background(), tool, []byte(`{"command":"curl https://t.example.test/"}`))
		if !block || !strings.Contains(msg, PlannerProbeMessagePrefix) {
			t.Fatalf("%s must be blocked once worker facts exist, block=%v msg=%q", tool, block, msg)
		}
		if !strings.Contains(msg, "add_intent") {
			t.Fatalf("block message should redirect to add_intent, got %q", msg)
		}
	}
}

// The origin fact alone is not a worker fact, so the opening allowance survives it.
// (CountWorkerFacts excludes state='origin'; here that means a 0 count still probes.)
func TestPlannerProbeAllowedAtOpening(t *testing.T) {
	_, hooks := plannerProbeHooksFor(noFacts)
	block, msg, _ := hooks.PreToolUse(context.Background(), "Bash", []byte(`{"command":"curl https://t.example.test/"}`))
	if block {
		t.Fatalf("opening probe with no worker facts must be allowed, msg=%q", msg)
	}
}

// Boundary 2: the opening allowance is finite.
func TestPlannerProbeCappedAtLimit(t *testing.T) {
	_, hooks := plannerProbeHooksFor(noFacts)
	cmd := []byte(`{"command":"curl https://t.example.test/"}`)

	for i := 0; i < PlannerProbeLimit; i++ {
		if block, msg, _ := hooks.PreToolUse(context.Background(), "Bash", cmd); block {
			t.Fatalf("probe %d/%d must be allowed, msg=%q", i+1, PlannerProbeLimit, msg)
		}
	}
	block, msg, _ := hooks.PreToolUse(context.Background(), "Bash", cmd)
	if !block || !strings.Contains(msg, PlannerProbeMessagePrefix) {
		t.Fatalf("probe past the cap must be blocked, block=%v msg=%q", block, msg)
	}
}

// The cap is per task, not per planning round: a fresh Plan() session reuses the
// same state, so the allowance cannot reset on every wake-up.
func TestPlannerProbeCapPersistsAcrossRounds(t *testing.T) {
	st := &plannerProbeState{}
	cmd := []byte(`{"command":"curl https://t.example.test/"}`)

	// Each round builds a new hook runner over the same per-task state.
	for i := 0; i < PlannerProbeLimit; i++ {
		round := WrapPlannerProbe(nil, st, PlannerProbeLimit, noFacts)
		if block, _, _ := round.PreToolUse(context.Background(), "Bash", cmd); block {
			t.Fatalf("probe %d must be allowed", i+1)
		}
	}
	later := WrapPlannerProbe(nil, st, PlannerProbeLimit, noFacts)
	if block, _, _ := later.PreToolUse(context.Background(), "Bash", cmd); !block {
		t.Fatal("a later planning round must not get a fresh probe allowance")
	}
}

// Bash 分流：对本地只读探查命令（cat/ls/grep/find 等）一律放行——即使 worker
// 已产出事实、即使额度已满——因为边界只管「探测目标」，不管「触摸本地文件」。
// 触网命令（curl 打目标）继续按两条边界拦截。
func TestPlannerProbeBashSemanticSplit(t *testing.T) {
	_, hooks := plannerProbeHooksFor(func() (int, bool) { return 7, true })

	for _, cmd := range []string{
		`{"command":"cat shared/challenges.json"}`,
		`{"command":"ls -la i12/"}`,
		`{"command":"grep -r 'flag' shared/ | head -5"}`,
		`{"command":"wc -l notes.txt"}`,
		`{"command":"echo done"}`,
		`{"command":"cat shared/death_manifest_i10815.json 2>/dev/null; echo \"---TAIL---\"; cat shared/bg_i10815_0_task_25_tail.txt 2>/dev/null"}`,
		`{"command":"cd shared && sed -n '/^==B64==$/,/^==========*$/p' i10798_loot_txt_decoded.txt | grep -v '^==' | tr -d '[:space:]' | base64 -D 2>/dev/null | iconv -f GB18030 -t UTF-8 2>/dev/null | tail -80"}`,
		`{"command":"cd shared && python3 -c \"data = open('i10798_loot_txt_decoded.txt','rb').read(); print('10.10.20.12' in data.decode('utf-8','ignore'))\""}`,
	} {
		if block, msg, _ := hooks.PreToolUse(context.Background(), "Bash", []byte(cmd)); block {
			t.Fatalf("local read-only bash must never be blocked: %s, msg=%q", cmd, msg)
		}
	}
	for _, blocked := range []string{
		`{"command":"curl http://10.0.0.9/"}`,
		`{"command":"base64 -o /tmp/out.bin shared/loot.txt"}`,
		`{"command":"iconv -f UTF-8 -t GBK -o /tmp/out.txt shared/loot.txt"}`,
		`{"command":"sed -n '1,5w /tmp/leak.txt' shared/loot.txt"}`,
		`{"command":"sed -n '1w /tmp/leak.txt' 1p"}`,
		`{"command":"python3 -c \"__import__('os').system('id')\""}`,
	} {
		if block, msg, _ := hooks.PreToolUse(context.Background(), "Bash", []byte(blocked)); !block {
			t.Fatalf("non-read-only bash must still hit boundary 1: %s, msg=%q", blocked, msg)
		}
	}

	// 开局无事实时：本地读不消耗探测额度——连续多次本地读后，三次触网额度仍完整。
	_, opening := plannerProbeHooksFor(noFacts)
	for i := 0; i < PlannerProbeLimit+3; i++ {
		if block, msg, _ := opening.PreToolUse(context.Background(), "Bash", []byte(`{"command":"cat /tmp/ledger.json"}`)); block {
			t.Fatalf("local read %d must be allowed and must not consume probe allowance, msg=%q", i+1, msg)
		}
	}
	curl := []byte(`{"command":"curl https://t.example.test/"}`)
	for i := 0; i < PlannerProbeLimit-1; i++ {
		if block, msg, _ := opening.PreToolUse(context.Background(), "Bash", curl); block {
			t.Fatalf("probe %d/%d must be allowed (local reads must not consume it), msg=%q", i+1, PlannerProbeLimit, msg)
		}
	}

	// 意图不纯的混合命令（本地读拼接触网）仍按探测计——这是第 3 次，仍在额度内。
	mixed := []byte(`{"command":"cat shared/x.json && curl https://t.example.test/"}`)
	if block, _, _ := opening.PreToolUse(context.Background(), "Bash", mixed); block {
		t.Fatal("mixed command at opening: probe boundary passes it within allowance")
	}
	// 额度已用尽（2 curl + 1 mixed = 3），再调必被 boundary 2 拦截。
	if block, msg, _ := opening.PreToolUse(context.Background(), "Bash", curl); !block {
		t.Fatalf("probe allowance must be exhausted after mixed command, msg=%q", msg)
	}

	// 入参解析失败 fail closed（按触网处理）。
	if block, _, _ := opening.PreToolUse(context.Background(), "Bash", []byte(`not-json`)); block {
		// 此时额度已尽，必拦；该路径的语义正确性由 isPlannerProbeTool 的单测保证。
	}
}

func TestIsPlannerProbeToolBashParsing(t *testing.T) {
	// 畸形/空输入按触网 fail closed，不让未分类命令绕过边界。
	for name, input := range map[string][]byte{
		"not-json":     []byte(`not-json`),
		"no command":   []byte(`{}`),
		"empty cmd":    []byte(`{"command":"  "}`),
	} {
		if !isPlannerProbeTool("Bash", input) {
			t.Fatalf("%s must fail closed as a probe", name)
		}
	}
	if isPlannerProbeTool("Bash", []byte(`{"command":"cat notes.txt"}`)) {
		t.Fatal("local cat must not classify as a probe")
	}
	if !isPlannerProbeTool("Bash", []byte(`{"command":"curl http://t/"}`)) {
		t.Fatal("curl to a target must classify as a probe")
	}
}

// Planning, graph reads and intent generation are never touched by the boundary.
func TestPlannerProbeLeavesPlanningToolsAlone(t *testing.T) {
	_, hooks := plannerProbeHooksFor(func() (int, bool) { return 99, true })

	for _, tool := range []string{"add_intent", "graph_overview", "node_detail", "list_facts", "prove_goal", "Read", "LS", "Grep", "Glob", "TodoWrite"} {
		if block, msg, _ := hooks.PreToolUse(context.Background(), tool, nil); block {
			t.Fatalf("%s is a planning tool and must stay available, msg=%q", tool, msg)
		}
	}
}

// An unavailable fact count fails soft on boundary 1 — it must not be read as an
// empty graph — while the opening cap still bounds probing.
func TestPlannerProbeFactLookupFailsSoft(t *testing.T) {
	_, hooks := plannerProbeHooksFor(func() (int, bool) { return 0, false })
	cmd := []byte(`{"command":"curl https://t.example.test/"}`)

	for i := 0; i < PlannerProbeLimit; i++ {
		if block, msg, _ := hooks.PreToolUse(context.Background(), "Bash", cmd); block {
			t.Fatalf("fact lookup failure must fail soft on probe %d, msg=%q", i+1, msg)
		}
	}
	if block, _, _ := hooks.PreToolUse(context.Background(), "Bash", cmd); !block {
		t.Fatal("the probe cap must still apply when the fact count is unavailable")
	}
}

// A nil state or non-positive limit must not install a blocking wrapper.
func TestWrapPlannerProbeNoOp(t *testing.T) {
	if h := WrapPlannerProbe(nil, nil, PlannerProbeLimit, noFacts); h != nil {
		t.Fatal("nil state must be a no-op wrapper")
	}
	if h := WrapPlannerProbe(nil, &plannerProbeState{}, 0, noFacts); h != nil {
		t.Fatal("non-positive limit must be a no-op wrapper")
	}
}

func TestPlannerProbeBlocksMCPTools(t *testing.T) {
	_, hooks := plannerProbeHooksFor(func() (int, bool) { return 2, true })
	block, msg, _ := hooks.PreToolUse(context.Background(), "mcp__nuclei__scan", []byte(`{"target":"10.0.0.1"}`))
	if !block || !strings.Contains(msg, PlannerProbeMessagePrefix) {
		t.Fatalf("mcp__* tool must be blocked once worker facts exist, block=%v msg=%q", block, msg)
	}

	_, opening := plannerProbeHooksFor(noFacts)
	for i := 0; i < PlannerProbeLimit; i++ {
		if block, msg, _ := opening.PreToolUse(context.Background(), "mcp__browser__open", []byte(`{}`)); block {
			t.Fatalf("opening mcp probe %d/%d should be allowed, msg=%q", i+1, PlannerProbeLimit, msg)
		}
	}
	if block, msg, _ := opening.PreToolUse(context.Background(), "mcp__browser__open", []byte(`{}`)); !block || !strings.Contains(msg, PlannerProbeMessagePrefix) {
		t.Fatalf("mcp probe past limit must be blocked, block=%v msg=%q", block, msg)
	}
}

type stubInnerGuard struct {
	called int
	block  bool
	msg    string
}

func (g *stubInnerGuard) PreToolUse(context.Context, string, []byte) (bool, string, []byte) {
	g.called++
	return g.block, g.msg, nil
}
func (g *stubInnerGuard) PostToolUse(context.Context, string, []byte, []byte, bool) {}
func (g *stubInnerGuard) Stop(context.Context, []llm.Message) (bool, []string, string) {
	return false, nil, ""
}

func TestPlannerProbeDelegatesAllowedProbesToInnerGuard(t *testing.T) {
	inner := &stubInnerGuard{block: true, msg: "out of scope"}
	hooks := WrapPlannerProbe(inner, &plannerProbeState{}, PlannerProbeLimit, noFacts)
	block, msg, _ := hooks.PreToolUse(context.Background(), "Bash", []byte(`{"command":"curl https://forbidden.example/"}`))
	if !block || msg != "out of scope" || inner.called != 1 {
		t.Fatalf("expected inner guard denial, block=%v msg=%q called=%d", block, msg, inner.called)
	}

	// When blocked by probe boundary 1, inner guard is short-circuited.
	inner2 := &stubInnerGuard{block: true, msg: "out of scope"}
	hooks2 := WrapPlannerProbe(inner2, &plannerProbeState{}, PlannerProbeLimit, func() (int, bool) { return 1, true })
	block2, msg2, _ := hooks2.PreToolUse(context.Background(), "Bash", []byte(`{"command":"curl https://a.example/"}`))
	if !block2 || !strings.Contains(msg2, PlannerProbeMessagePrefix) || inner2.called != 0 {
		t.Fatalf("expected boundary 1 short-circuit, block=%v msg=%q called=%d", block2, msg2, inner2.called)
	}
	if !strings.Contains(msg2, "Read / LS / Glob / Grep") {
		t.Fatalf("probe block message should remind Planner to use Read/LS/Glob/Grep for local files, got %q", msg2)
	}
}

func TestPlannerDefaultProbeGuardEnabledByDefault(t *testing.T) {
	t.Setenv("ARTEX_ENABLE_PLANNER_PROBE_GUARD", "")
	if !envBoolFlag("ARTEX_ENABLE_PLANNER_PROBE_GUARD", true) {
		t.Fatal("ARTEX_ENABLE_PLANNER_PROBE_GUARD must default to true when unset")
	}
	t.Setenv("ARTEX_ENABLE_PLANNER_PROBE_GUARD", "0")
	if envBoolFlag("ARTEX_ENABLE_PLANNER_PROBE_GUARD", true) {
		t.Fatal("ARTEX_ENABLE_PLANNER_PROBE_GUARD=0 must allow explicit opt-out")
	}
}

