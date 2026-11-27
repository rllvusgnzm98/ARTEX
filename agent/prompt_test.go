package agent

import (
	"strings"
	"testing"
)

func TestRenderSystemOverrideAndFallback(t *testing.T) {
	t.Cleanup(func() { PromptOverride = nil })

	// no override → built-in default
	PromptOverride = nil
	if got := renderSystem("planner", "DEFAULT", PlannerVars{Goal: "g"}); got != "DEFAULT" {
		t.Fatalf("no override should give default, got %q", got)
	}

	// override → rendered with vars
	PromptOverride = func(k string) (string, bool) {
		if k == "planner" {
			return "目标:{{.Goal}} 范围:{{.Scope}}", true
		}
		return "", false
	}
	if got := renderSystem("planner", "DEFAULT", PlannerVars{Goal: "拿下X", Scope: "*.x.com"}); got != "目标:拿下X 范围:*.x.com" {
		t.Fatalf("override render: %q", got)
	}

	// override referencing a non-catalog var → execution error → fallback to default
	PromptOverride = func(k string) (string, bool) { return "{{.NotInCatalog}}", true }
	if got := renderSystem("planner", "DEFAULT", PlannerVars{Goal: "x"}); got != "DEFAULT" {
		t.Fatalf("bad var should fall back to default, got %q", got)
	}

	// full plannerSystem path: DB body [A] is honored, then the code-owned tail
	// [C] (中间产物输出规约) is ALWAYS appended — editing the body can't drop it.
	PromptOverride = func(k string) (string, bool) { return "PLANNER {{.Goal}}", true }
	got := plannerSystem("拿下X", "/data", "/data")
	if !strings.HasPrefix(got, "PLANNER 拿下X") {
		t.Fatalf("plannerSystem body not honored: %q", got)
	}
	if !strings.Contains(got, "中间产物输出规约") || !strings.Contains(got, "/data") {
		t.Fatalf("plannerSystem missing code-owned artifact tail: %q", got)
	}

	// worker dual-text via {{if .ProxyAddr}} in a user template, plus the code tail:
	// [B] trafficTool present only when RECORDING (caCert set — the MITM is on, so
	// the traffic_* tools exist), [C] artifact spec always present. The trafficTool
	// block is gated on the CA (arg 2), NOT on ProxyAddr — a global egress proxy
	// with capture off routes traffic but records nothing.
	PromptOverride = func(k string) (string, bool) {
		return "{{if .ProxyAddr}}走代理 {{.ProxyAddr}}{{else}}手动{{end}}", true
	}
	recording := workerSystem("127.0.0.1:8080", "/ca.pem", "/data", "/data", false, DefaultFootprint())
	if !strings.HasPrefix(recording, "走代理 127.0.0.1:8080") {
		t.Fatalf("worker proxy branch body: %q", recording)
	}
	if !strings.Contains(recording, "traffic_search") {
		t.Fatalf("worker while recording should inject trafficTool: %q", recording)
	}
	if strings.Contains(recording, "traffic_refs") {
		t.Fatalf("worker bypassed shared optional evidence policy: %q", recording)
	}
	if !strings.Contains(recording, "中间产物输出规约") {
		t.Fatalf("worker missing artifact tail: %q", recording)
	}
	// Egress proxy set but capture OFF (no CA): the ProxyAddr template branch still
	// renders, but the trafficTool block must NOT — those tools are not registered.
	egressOnly := workerSystem("127.0.0.1:8080", "", "/data", "/data", false, DefaultFootprint())
	if !strings.HasPrefix(egressOnly, "走代理 127.0.0.1:8080") {
		t.Fatalf("worker egress-only branch body: %q", egressOnly)
	}
	if strings.Contains(egressOnly, "traffic_search") {
		t.Fatalf("worker without recording must NOT inject trafficTool: %q", egressOnly)
	}
	noProxy := workerSystem("", "", "/data", "/data", false, DefaultFootprint())
	if !strings.HasPrefix(noProxy, "手动") {
		t.Fatalf("worker no-proxy branch body: %q", noProxy)
	}
	if strings.Contains(noProxy, "traffic_search") {
		t.Fatalf("worker without proxy must NOT inject trafficTool: %q", noProxy)
	}
}

func TestWorkerSystemIntranetVariant(t *testing.T) {
	t.Cleanup(func() { PromptOverride = nil })

	PromptOverride = nil
	got := workerSystem("", "", "/data", "/data", true, DefaultFootprint())
	if !strings.Contains(got, "内网红线") {
		t.Fatalf("有活会话时缺少代码固定内网红线尾: %q", got)
	}
	if !strings.Contains(got, "内网期纪律") {
		t.Fatalf("有活会话时应追加 worker.intranet 短纪律: %q", got)
	}
	// 变体只追加,不得替换 worker 默认正文。
	if !strings.Contains(got, "执行者") {
		t.Fatalf("内网变体不得覆盖 worker 主正文: %q", got)
	}
	if strings.Contains(got, "批准前不得") || strings.Contains(got, "不得对其主动探测") || strings.Contains(got, "tunnel_deploy") || strings.Contains(got, "隧道四件套") {
		t.Fatalf("纪律不得把 pending_scope 写成硬门闩,也不得提隧道四件套: %q", got)
	}

	// worker.intranet 覆盖只作用于追加段,不能抢走 worker 正文。
	PromptOverride = func(k string) (string, bool) {
		switch k {
		case "worker.intranet":
			return "内网正文覆盖 {{.Intranet}}", true
		case "worker":
			return "外网正文", true
		}
		return "", false
	}
	if got = workerSystem("", "", "/data", "/data", true, DefaultFootprint()); !strings.HasPrefix(got, "外网正文") {
		t.Fatalf("worker 正文仍应由 worker 键渲染: %q", got)
	}
	if !strings.Contains(got, "内网正文覆盖 true") {
		t.Fatalf("worker.intranet 覆盖应出现在追加段: %q", got)
	}
	if !strings.Contains(got, "内网红线") {
		t.Fatalf("编辑变体正文也删不掉代码固定内网红线尾: %q", got)
	}

	// 变体缺失时退回内置纪律,并仍追加红线尾。
	PromptOverride = func(k string) (string, bool) {
		if k == "worker" {
			return "外网正文", true
		}
		return "", false
	}
	if got = workerSystem("", "", "/data", "/data", true, DefaultFootprint()); !strings.HasPrefix(got, "外网正文") {
		t.Fatalf("缺失变体时应退回 worker 正文: %q", got)
	}
	if !strings.Contains(got, "内网期纪律") || !strings.Contains(got, "内网红线") {
		t.Fatalf("缺失变体时应追加内置纪律与红线尾: %q", got)
	}

	// intranet=false 不追加纪律或红线尾。
	if got = workerSystem("", "", "/data", "/data", false, DefaultFootprint()); strings.Contains(got, "内网红线") || strings.Contains(got, "内网期纪律") {
		t.Fatalf("无活会话不得追加内网变体: %q", got)
	}

	// 进场预塞与「图谱不完整」标记在内网变体下仍追加在既有位置、语义不变。
	incomplete := RenderWorkerEntrySeed(WorkerEntrySeed{
		GraphIncomplete:   true,
		IncompleteReasons: []string{"prefetch"},
		Prefetched:        false,
	})
	assembled := workerSystem("", "", "/data", "/data", true, DefaultFootprint()) + incomplete
	if !strings.Contains(assembled, "内网红线") {
		t.Fatalf("拼接后应保留内网变体:\n%s", assembled)
	}
	if !strings.Contains(assembled, GraphIncompleteMarker) {
		t.Fatalf("内网变体下「图谱不完整」标记必须仍在:\n%s", assembled)
	}
	// 预塞段在变体之后追加(与 execute() 既有顺序一致),变体不得覆盖预塞。
	idxVariant := strings.Index(assembled, "内网期纪律")
	idxSeed := strings.Index(assembled, GraphIncompleteMarker)
	if idxVariant < 0 || idxSeed < 0 || idxSeed < idxVariant {
		t.Fatalf("进场预塞应保持在变体之后的既有位置, variant=%d seed=%d", idxVariant, idxSeed)
	}
}

func TestIntranetResolverIsRequeriedEachRun(t *testing.T) {
	var w Worker
	if w.intranetForTask(7) {
		t.Fatal("未设置 resolver 时应保持外网默认")
	}
	calls := 0
	w.SetIntranetResolver(func(taskID int64) bool {
		calls++
		return taskID == 7 && calls >= 2
	})
	if w.intranetForTask(7) {
		t.Fatal("resolver 第一次应返回 false")
	}
	if !w.intranetForTask(7) {
		t.Fatal("resolver 必须每次 run 现查,第二次应为 true")
	}
	if w.intranetForTask(8) {
		t.Fatal("其他 task 不得误切内网变体")
	}
	if calls != 3 {
		t.Fatalf("intranetFn 应被调用 3 次, got %d", calls)
	}
}

func TestPlannerNextHopDisciplineWording(t *testing.T) {
	got := plannerSystem("核验已确认主机", "/data", "/data")
	if !strings.Contains(got, "derived_from") || !strings.Contains(got, "parent_ids") || !strings.Contains(got, "asset_ids") {
		t.Fatalf("规划器应要求下一跳挂 derived_from 或资产锚:\n%s", got)
	}
	if !strings.Contains(got, "不要假设读取侧已对任意后续意图闭环") {
		t.Fatalf("规划器应明确读取侧未对任意后续意图闭环:\n%s", got)
	}
	if strings.Contains(got, "读取侧已经闭环") || strings.Contains(got, "读取侧已闭环") {
		t.Fatalf("不得宣称读取侧已闭环:\n%s", got)
	}
}

func TestRedTeamCommandSeatSharesPlannerWhiteboardAndTools(t *testing.T) {
	// 1. MainAgentTools includes Red Team Lead authority tools alongside human ops.
	names := map[string]bool{}
	for _, tool := range NewToolSet(nil, "").MainAgentTools() {
		names[tool.Name()] = true
	}
	for _, want := range []string{"kill_work", "prove_goal", "list_goals", "steer_work", "add_intent", "add_task_scope"} {
		if !names[want] {
			t.Errorf("MainAgentTools missing Red Team Lead tool %q", want)
		}
	}

	// 2. Planner.TodoFor(expID) returns the exact shared TodoStore across command seat & planner.
	p := NewPlanner(nil, "m", t.TempDir(), nil, 0, 0)
	s1 := p.TodoFor(42)
	s2 := p.TodoFor(42)
	if s1 == nil || s1 != s2 {
		t.Fatalf("TodoFor must return the same per-exploration whiteboard store")
	}

	// 3. Red Team doctrine wording checks on planner, worker, mainagent templates.
	t.Cleanup(func() { PromptOverride = nil })
	PromptOverride = nil
	plan := plannerSystem("Auditing *.acme.com", "/data", "/data")
	if !strings.Contains(plan, `严禁下发"让 worker 自己拉目标列表挑一个打`) || !strings.Contains(plan, "严禁调 TodoWrite 空刷清单") {
		t.Errorf("planner prompt missing anti-self-scheduling or anti-TodoWrite-spam doctrine:\n%s", plan)
	}
	work := workerSystem("", "", "/data", "/data", false, DefaultFootprint())
	if !strings.Contains(work, "一单只打一靶") || !strings.Contains(work, "Signal Gate") || !strings.Contains(work, "js-api-recon") {
		t.Errorf("worker prompt missing Red Team operator / H1 Signal / Skill guidance:\n%s", work)
	}
	main := mainAgentSystem("Auditing *.acme.com", "/data", "/data")
	if !strings.Contains(main, "红队队长") || !strings.Contains(main, "kill_work") {
		t.Errorf("mainagent prompt missing Red Team command seat wording:\n%s", main)
	}
}

func TestPromptPolishWorkerPlannerAndScopeSource(t *testing.T) {
	t.Cleanup(func() { PromptOverride = nil })
	PromptOverride = nil

	work := workerSystem("", "", "/data", "/data/tasks/1/i9", false, DefaultFootprint())
	if strings.Contains(work, "tbhm-recon") {
		t.Fatalf("worker prompt must not reference unbound dead skill tbhm-recon:\n%s", work)
	}
	if !strings.Contains(work, "按需") {
		t.Fatalf("worker prompt should mention on-demand skills:\n%s", work)
	}

	plan := plannerSystem("内网域控评估", "/data", "/data/tasks/1")
	for _, want := range []string{"授权范围外", "shared/", "disputed", "kill_work"} {
		if !strings.Contains(plan, want) {
			t.Fatalf("planner prompt missing polish wording %q:\n%s", want, plan)
		}
	}

	ts := NewToolSet(nil, "goals")
	ts.SetScopeSource(" seed ")
	if ts.scopeSource != "seed" {
		t.Fatalf("SetScopeSource got %q, want seed", ts.scopeSource)
	}
}
