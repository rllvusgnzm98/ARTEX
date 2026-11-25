package agent

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// multiStageGraph is the acceptance fixture: two hosts, a prior worker's
// confirmed fact, and an undelivered follow-on target. No challenge/recipe data.
func multiStageGraph() (EntryGraph, []int64) {
	intentA := node(100, db.KindIntent, "done", map[string]any{
		"summary":   "确认边缘主机可达性",
		"asset_ids": []int64{11},
	})
	factA := node(201, db.KindFact, "confirmed", map[string]any{
		"summary":    "边缘主机 edge.example.test 已可达，并观察到应用主机 app.example.test 可从该边缘继续访问",
		"detail":     "edge.example.test:443 响应正常；同范围内 app.example.test 亦可达，但尚未对其做后续核验",
		"confidence": "observed",
		"evidence":   "probe edge.example.test:443 → 200",
	})
	intentB := node(102, db.KindIntent, "open", map[string]any{
		"summary":   "在已确认可达的应用主机上继续核验，不要把该主机当新目标重开",
		"asset_ids": []int64{22},
	})
	unrelated := node(301, db.KindFact, "confirmed", map[string]any{
		"summary":    "无关网段的一次推断",
		"confidence": "inferred",
	})
	origin := node(1, db.KindFact, db.StateOrigin, map[string]any{
		"summary": "task origin",
	})
	goal := node(9, db.KindGoal, "open", map[string]any{
		"text": "核验已暴露服务的授权范围内风险",
	})
	g := EntryGraph{
		Intent:         intentB,
		IntentAssetIDs: []int64{22},
		Facts:          []*db.Node{origin, factA, unrelated},
		Findings:       nil,
		Goals:          []*db.Node{goal},
		Edges: []db.Edge{
			{From: intentA.ID, Rel: db.RelYields, To: factA.ID},
			{From: factA.ID, Rel: db.RelDerivedFrom, To: intentB.ID},
		},
		Anchors: map[int64][]int64{
			intentA.ID: {11},
			factA.ID:   {11, 22},
			intentB.ID: {22},
		},
		Assets: map[int64]string{
			11: "edge.example.test",
			22: "app.example.test",
		},
	}
	return g, []int64{11, 22}
}

func node(id int64, kind, state string, payload map[string]any) *db.Node {
	raw, _ := json.Marshal(payload)
	return &db.Node{ID: id, Kind: kind, State: state, Payload: raw}
}

func TestWorkerToolsIncludesFactReadback(t *testing.T) {
	names := map[string]bool{}
	for _, tool := range NewToolSet(nil, "").WorkerTools() {
		names[tool.Name()] = true
	}
	for _, want := range []string{"list_facts", "list_companies", "list_assets", "list_findings", "node_detail"} {
		if !names[want] {
			t.Errorf("WorkerTools missing %s", want)
		}
	}
	if names["list_worker_traces"] {
		t.Error("WorkerTools must not re-introduce list_worker_traces")
	}
}

func TestBuiltinSeedsBindWorkerListFacts(t *testing.T) {
	byKey := map[string]ToolSeed{}
	for _, s := range BuiltinToolSeeds() {
		byKey[s.Key] = s
	}
	for _, key := range []string{"list_facts", "list_companies"} {
		seed, ok := byKey[key]
		if !ok {
			t.Fatalf("%s not in BuiltinToolSeeds", key)
		}
		hasWorker := false
		for _, a := range seed.Agents {
			if a == "worker" {
				hasWorker = true
			}
		}
		if !hasWorker {
			t.Errorf("%s agents=%v, want worker", key, seed.Agents)
		}
	}
}

func TestEntrySeedPresentsPriorConfirmedFactsAndNextHop(t *testing.T) {
	g, neighborhood := multiStageGraph()
	seed := BuildWorkerEntrySeed(g)
	if !seed.Prefetched || seed.GraphIncomplete {
		t.Fatalf("seed should be complete: %+v", seed)
	}
	if len(seed.Writes) != 0 {
		t.Fatalf("prefetch must be read-only, writes=%v", seed.Writes)
	}
	if len(seed.ConfirmedFacts) != 1 || seed.ConfirmedFacts[0].ID != 201 {
		t.Fatalf("expected worker A's confirmed fact, got %+v", seed.ConfirmedFacts)
	}
	if !strings.Contains(seed.ConfirmedFacts[0].Summary, "edge.example.test") {
		t.Errorf("worker B must see worker A's confirmed fact, got %q", seed.ConfirmedFacts[0].Summary)
	}

	prompt := RenderWorkerEntrySeed(seed)
	if !strings.Contains(prompt, "edge.example.test 已可达") {
		t.Errorf("prompt missing worker A fact:\n%s", prompt)
	}
	if !strings.Contains(prompt, "app.example.test") {
		t.Errorf("prompt missing follow-on host:\n%s", prompt)
	}
	if !strings.Contains(prompt, "下一跳接着打") || !strings.Contains(prompt, "不要当新目标重开") {
		t.Errorf("next hop must be framed as continuation, not a new target:\n%s", prompt)
	}
	if !strings.Contains(prompt, "【进场硬步骤】") || !strings.Contains(prompt, "list_facts") {
		t.Errorf("hard-step wording missing:\n%s", prompt)
	}

	// Repeat-scan contrast: no-read seed treats both confirmed hosts as needing a probe.
	empty := WorkerEntrySeed{}
	noRead := RepeatScanRisk(empty, neighborhood)
	withRead := RepeatScanRisk(seed, neighborhood)
	if noRead < 2 {
		t.Fatalf("no-read contrast risk=%d, want at least 2 confirmed hosts", noRead)
	}
	if withRead >= noRead || withRead != 0 {
		t.Fatalf("read-side risk=%d should drop vs no-read=%d and be 0", withRead, noRead)
	}

	if !GraphReadBeforeSideEffect(seed, []string{"Bash"}) {
		t.Error("successful prefetch must count as the graph read before any side-effect tool")
	}
	if GraphReadBeforeSideEffect(WorkerEntrySeed{}, []string{"Bash"}) {
		t.Error("no-read contrast must not treat a first Bash call as a graph read")
	}
	if !GraphReadBeforeSideEffect(WorkerEntrySeed{}, []string{"list_facts", "Bash"}) {
		t.Error("list_facts before Bash should satisfy the hard step")
	}

	var sawApp, sawEdge bool
	for _, h := range seed.NextHops {
		if h.Label == "app.example.test" && h.Continuation {
			sawApp = true
		}
		if h.Label == "edge.example.test" && h.Continuation {
			sawEdge = true
		}
	}
	if !sawApp || !sawEdge {
		t.Fatalf("both confirmed-reachable hosts should be next-hop continuations, got %+v", seed.NextHops)
	}
}

func TestEntrySeedOmitsInferredAndOriginFacts(t *testing.T) {
	g, _ := multiStageGraph()
	seed := BuildWorkerEntrySeed(g)
	for _, f := range seed.ConfirmedFacts {
		if f.ID == 1 || f.ID == 301 {
			t.Fatalf("origin/inferred fact leaked into pre-seed: %+v", f)
		}
	}
}

func TestEntrySeedMarksDeliveredAssetsOutOfNextHop(t *testing.T) {
	g, _ := multiStageGraph()
	g.Findings = []*db.Node{node(401, db.KindFinding, "confirmed", map[string]any{
		"summary": "already delivered on the edge host",
	})}
	g.Anchors[401] = []int64{11}
	seed := BuildWorkerEntrySeed(g)
	for _, h := range seed.NextHops {
		if h.AssetID == 11 {
			t.Fatalf("delivered edge host must not appear as undelivered next hop: %+v", seed.NextHops)
		}
	}
	foundApp := false
	for _, h := range seed.NextHops {
		if h.AssetID == 22 {
			foundApp = true
		}
	}
	if !foundApp {
		t.Fatalf("undelivered app host should remain a next hop: %+v", seed.NextHops)
	}
}

func TestEntrySeedFailSoftIncompleteGraph(t *testing.T) {
	g, _ := multiStageGraph()
	g.CompressErr = errors.New("compressor unavailable")
	g.PrefetchErr = errors.New("list facts failed")
	seed := BuildWorkerEntrySeed(g)
	if !seed.GraphIncomplete {
		t.Fatal("expected 图谱不完整")
	}
	if seed.Prefetched {
		t.Fatal("prefetch error must not claim a successful prefetch")
	}
	if len(seed.Writes) != 0 {
		t.Fatalf("fail-soft must not write target/goal failure, writes=%v", seed.Writes)
	}
	prompt := RenderWorkerEntrySeed(seed)
	if !strings.Contains(prompt, "「"+GraphIncompleteMarker+"」") && !strings.Contains(prompt, "【"+GraphIncompleteMarker+"】") {
		t.Fatalf("marker missing:\n%s", prompt)
	}
	if !strings.Contains(prompt, GraphIncompleteMarker) {
		t.Fatalf("marker %q missing:\n%s", GraphIncompleteMarker, prompt)
	}
	if !strings.Contains(prompt, "进场不被阻断") {
		t.Fatalf("must say entry is not blocked:\n%s", prompt)
	}
	if !strings.Contains(prompt, "不要把这次失败记录为目标失败") {
		t.Fatalf("must not frame the failure as a target failure:\n%s", prompt)
	}
	if strings.Contains(prompt, "目标失败") && !strings.Contains(prompt, "不要把这次失败记录为目标失败") {
		t.Fatalf("unexpected target-failure wording:\n%s", prompt)
	}
	// Incomplete prefetch is not enough: the first side-effect still needs a graph read.
	if GraphReadBeforeSideEffect(seed, []string{"Bash"}) {
		t.Error("failed prefetch must not count as a completed graph read")
	}
	if !GraphReadBeforeSideEffect(seed, []string{"list_facts", "Bash"}) {
		t.Error("list_facts after a failed prefetch should still satisfy the hard step")
	}
}

func TestSingleHostRangeIsContrastOnly(t *testing.T) {
	// A single-host graph may exist as a contrast, but it is not the acceptance fixture.
	intent := node(2, db.KindIntent, "open", map[string]any{"summary": "only one host", "asset_ids": []int64{11}})
	fact := node(3, db.KindFact, "confirmed", map[string]any{
		"summary":    "edge.example.test reachable",
		"confidence": "observed",
	})
	single := EntryGraph{
		Intent:         intent,
		IntentAssetIDs: []int64{11},
		Facts:          []*db.Node{fact},
		Edges:          []db.Edge{{From: fact.ID, Rel: db.RelDerivedFrom, To: intent.ID}},
		Anchors:        map[int64][]int64{fact.ID: {11}, intent.ID: {11}},
		Assets:         map[int64]string{11: "edge.example.test"},
	}
	multi, neighborhood := multiStageGraph()
	if len(uniqueIDs(append(single.IntentAssetIDs, 11))) < 2 && len(neighborhood) < 2 {
		t.Fatal("fixture helper broken")
	}
	if len(BuildWorkerEntrySeed(single).NextHops) == 0 {
		t.Fatal("single-host contrast should still pre-seed its one hop")
	}
	if len(uniqueIDs(neighborhood)) < 2 {
		t.Fatal("acceptance fixture must be multi-host")
	}
	if len(BuildWorkerEntrySeed(multi).ConfirmedFacts) == 0 {
		t.Fatal("acceptance fixture should carry a prior confirmed fact")
	}
}

func TestWorkerToolsListFactsIsCallableShape(t *testing.T) {
	// Guards the tool identity without hitting a store: the handler must exist.
	var facts, companies actool.CoreTool
	for _, tool := range NewToolSet(nil, "").WorkerTools() {
		switch tool.Name() {
		case "list_facts":
			facts = tool
		case "list_companies":
			companies = tool
		}
	}
	if facts == nil || companies == nil {
		t.Fatal("list_facts/list_companies must be constructed for workers")
	}
	if facts.Description() == "" || companies.Description() == "" {
		t.Fatal("tools need descriptions")
	}
}

func TestEntrySeedFallbackMatchesPayloadHostWithBoundaries(t *testing.T) {
	// Un-anchored continuation intent (no asset_ids, no derived_from edges)
	// should still recover matching asset hosts from its summary while obeying
	// host/IP token boundaries (10.0.164.13 must NOT match 10.0.164.138).
	intent := node(795, db.KindIntent, "open", map[string]any{
		"summary": "续解 c-06（HugeGraph 1.2.0，10.0.164.138:8080）",
	})
	factMatched := node(794, db.KindFact, "confirmed", map[string]any{
		"summary":    "c-06 拿到 admin_token",
		"confidence": "observed",
	})
	factPrefixTrap := node(799, db.KindFact, "confirmed", map[string]any{
		"summary":    "无关主机 10.0.164.13 上的观察",
		"confidence": "observed",
	})
	g := EntryGraph{
		Intent: intent,
		Facts:  []*db.Node{factMatched, factPrefixTrap},
		Anchors: map[int64][]int64{
			factMatched.ID:    {10},
			factPrefixTrap.ID: {20},
		},
		Assets: map[int64]string{
			10: "http://10.0.164.138:8080",
			20: "10.0.164.13",
		},
	}
	seed := BuildWorkerEntrySeed(g)
	if len(seed.ConfirmedFacts) != 1 || seed.ConfirmedFacts[0].ID != factMatched.ID {
		t.Fatalf("fallback host match mismatch: got %+v, want only fact #%d", seed.ConfirmedFacts, factMatched.ID)
	}
}

func TestEntrySeedIsolatesUnrelatedHostKeyFactsAndSharedIP(t *testing.T) {
	// Scenario: blog.acme.test and pay.acme.test sit behind shared IP 104.18.0.1.
	// Testing pay.acme.test must NOT pull blog.acme.test's host-anchored negative_result,
	// evidence-bearing facts, or sibling NextHops / shared CDN IP, while still retaining
	// scope_limit and unanchored task-global key facts.
	const (
		blogID   = int64(10)
		payID    = int64(20)
		sharedIP = int64(30)
	)
	intentPay := node(500, db.KindIntent, "open", map[string]any{
		"summary":   "审计 pay.acme.test 支付接口越权",
		"asset_ids": []int64{payID},
	})
	factBlogNeg := node(501, db.KindFact, "confirmed", map[string]any{
		"summary":    "blog.acme.test 登录接口未发现注入",
		"category":   "negative_result",
		"confidence": "observed",
	})
	factBlogEv := node(502, db.KindFact, "confirmed", map[string]any{
		"summary":      "blog.acme.test CMS 版本响应包",
		"confidence":   "observed",
		"evidence_ids": []string{"traffic:101"},
	})
	factBlogGeneral := node(503, db.KindFact, "confirmed", map[string]any{
		"summary":    "blog.acme.test 使用 Ghost 运行在 104.18.0.1",
		"confidence": "observed",
	})
	factPayGeneral := node(504, db.KindFact, "confirmed", map[string]any{
		"summary":    "pay.acme.test 解析至 104.18.0.1",
		"confidence": "observed",
	})
	factScope := node(505, db.KindFact, "confirmed", map[string]any{
		"summary":    "全任务 WAF 限速 5 req/s（测试 blog.acme.test 时观测）",
		"category":   "scope_limit",
		"confidence": "observed",
	})
	factGlobalNeg := node(506, db.KindFact, "confirmed", map[string]any{
		"summary":    "全局禁止测试 /admin/shutdown 破坏性端点",
		"category":   "negative_result",
		"confidence": "observed",
	})

	g := EntryGraph{
		Intent:         intentPay,
		IntentAssetIDs: []int64{payID},
		Facts:          []*db.Node{factBlogNeg, factBlogEv, factBlogGeneral, factPayGeneral, factScope, factGlobalNeg},
		Anchors: map[int64][]int64{
			factBlogNeg.ID:     {blogID},
			factBlogEv.ID:      {blogID},
			factBlogGeneral.ID: {blogID, sharedIP},
			factPayGeneral.ID:  {payID, sharedIP},
			factScope.ID:       {blogID},
		},
		Assets: map[int64]string{
			blogID:   "blog.acme.test",
			payID:    "pay.acme.test",
			sharedIP: "104.18.0.1",
		},
		AssetTypes: map[int64]string{
			blogID:   "subdomain",
			payID:    "subdomain",
			sharedIP: "ip",
		},
	}

	seed := BuildWorkerEntrySeed(g)
	gotFacts := map[int64]bool{}
	for _, f := range seed.ConfirmedFacts {
		gotFacts[f.ID] = true
	}
	for _, want := range []int64{factPayGeneral.ID, factScope.ID, factGlobalNeg.ID} {
		if !gotFacts[want] {
			t.Errorf("expected fact #%d in pay.acme.test seed, got %v", want, gotFacts)
		}
	}
	for _, unwanted := range []int64{factBlogNeg.ID, factBlogEv.ID, factBlogGeneral.ID} {
		if gotFacts[unwanted] {
			t.Errorf("unrelated-host fact #%d leaked into pay.acme.test seed: %+v", unwanted, gotFacts)
		}
	}
	for _, hop := range seed.NextHops {
		if hop.AssetID == blogID || hop.AssetID == sharedIP {
			t.Errorf("unrelated host or shared CDN IP leaked into NextHops: %+v", hop)
		}
	}
}

func TestEntrySeedIsolatesWorkerYieldedUnanchoredCleanupAndNegativeFacts(t *testing.T) {
	intentOther := node(100, db.KindIntent, "done", map[string]any{"summary": "test target A"})
	intentNew := node(101, db.KindIntent, "open", map[string]any{"summary": "test unrelated target B"})
	intentCont := node(102, db.KindIntent, "open", map[string]any{"summary": "continue target A"})

	factCleanup := node(201, db.KindFact, "confirmed", map[string]any{
		"summary":    "target A container stopped",
		"category":   "cleanup_status",
		"confidence": "observed",
	})
	factNeg := node(202, db.KindFact, "confirmed", map[string]any{
		"summary":    "target A /login not sqli",
		"category":   "negative_result",
		"confidence": "observed",
	})
	factScope := node(203, db.KindFact, "confirmed", map[string]any{
		"summary":    "rate limit max 3 concurrent",
		"category":   "scope_limit",
		"confidence": "observed",
	})

	edges := []db.Edge{
		{From: intentOther.ID, Rel: db.RelYields, To: factCleanup.ID},
		{From: intentOther.ID, Rel: db.RelYields, To: factNeg.ID},
		{From: intentOther.ID, Rel: db.RelYields, To: factScope.ID},
		{From: factNeg.ID, Rel: db.RelDerivedFrom, To: intentCont.ID},
	}
	facts := []*db.Node{factCleanup, factNeg, factScope}

	// Unrelated intentNew receives ONLY scope_limit, not worker-yielded cleanup_status / negative_result.
	seedNew := BuildWorkerEntrySeed(EntryGraph{Intent: intentNew, Facts: facts, Edges: edges})
	gotNew := map[int64]bool{}
	for _, f := range seedNew.ConfirmedFacts {
		gotNew[f.ID] = true
	}
	if !gotNew[factScope.ID] {
		t.Fatalf("unrelated intent must receive scope_limit, got %v", gotNew)
	}
	if gotNew[factCleanup.ID] || gotNew[factNeg.ID] {
		t.Fatalf("worker-yielded unanchored cleanup/negative leaked to unrelated intent: %v", gotNew)
	}

	// Continuation intentCont linked via derived_from still receives sibling facts from intentOther.
	seedCont := BuildWorkerEntrySeed(EntryGraph{Intent: intentCont, Facts: facts, Edges: edges})
	gotCont := map[int64]bool{}
	for _, f := range seedCont.ConfirmedFacts {
		gotCont[f.ID] = true
	}
	for _, id := range []int64{factCleanup.ID, factNeg.ID, factScope.ID} {
		if !gotCont[id] {
			t.Fatalf("continuation intent missing lineage fact #%d: got %v", id, gotCont)
		}
	}
}
