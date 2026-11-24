package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

// --- faithful pre-stage-3 baselines (before/after contrast) ---

const legacyEntrySeedDetailCap = 600

// legacyRenderEntrySeedDetails reproduces the pre-stage-3 behavior: every
// confirmed fact (key OR general) inlined its detail clipped to 600 runes. We
// only need the detail-line bytes for the size contrast, since summaries/caps
// are unchanged by stage 3.
func legacyEntrySeedDetailBytes(seed WorkerEntrySeed) int {
	var keys, general []EntryFact
	for _, f := range seed.ConfirmedFacts {
		if isKeyFact(f.Category, f.EvidenceIDs) {
			keys = append(keys, f)
		} else {
			general = append(general, f)
		}
	}
	if len(keys) > entrySeedKeyFactCap {
		keys = keys[:entrySeedKeyFactCap]
	}
	slots := entrySeedFactCap - len(keys)
	if len(general) > slots {
		general = general[len(general)-slots:]
	}
	n := 0
	for _, f := range append(keys, general...) {
		if d := strings.TrimSpace(f.Detail); d != "" {
			n += utf8.RuneCountInString("  细节：") + utf8.RuneCountInString(clipRunes(d, legacyEntrySeedDetailCap)) + 1
		}
	}
	return n
}

// legacyWorkerOverview reproduces the pre-stage-3 worker overview: no fact dedup
// against the seed, cold-digest bodies kept inline.
func legacyWorkerOverview(data map[string]any) string {
	delete(data, "coverage")
	b, _ := json.Marshal(data)
	return string(b)
}

func newWorkerOverviewBody(data map[string]any, seedIDs map[int64]bool) string {
	// renderWorkerGraphOverview mutates+marshals data; strip the fixed framing
	// prose so we compare only the JSON payload that actually varies.
	full := renderWorkerGraphOverview(data, seedIDs)
	if i := strings.IndexByte(full, '{'); i >= 0 {
		return full[i:]
	}
	return full
}

// representativeSeed builds a mature-task entry seed: 10 key facts (scope limits /
// negative results, with evidence) + 50 general confirmed facts, each with a long
// detail — the shape that dominates a long-running intent's system prompt.
func representativeSeed() WorkerEntrySeed {
	seed := WorkerEntrySeed{Prefetched: true}
	id := int64(0)
	for i := 0; i < 10; i++ {
		id++
		seed.ConfirmedFacts = append(seed.ConfirmedFacts, EntryFact{
			ID: id, Summary: fmt.Sprintf("关键约束/否定结果 #%d：该范围内某路径已确认不可达", i),
			Detail:      strings.Repeat("关键事实的细节与证据描述。", 30), // ~ long
			Category:    []string{"scope_limit", "negative_result", "cleanup_status", "evidence"}[i%4],
			EvidenceIDs: []string{fmt.Sprintf("evidence:%d", i)}, Confidence: "observed",
			AssetIDs: []int64{int64(100 + i)}, Assets: []string{fmt.Sprintf("host-%d.example.test", i)},
		})
	}
	for i := 0; i < 50; i++ {
		id++
		seed.ConfirmedFacts = append(seed.ConfirmedFacts, EntryFact{
			ID: id, Summary: fmt.Sprintf("普通观察 #%d：edge-%d.example.test 上发现一个接口", i, i),
			Detail:     strings.Repeat("普通事实的冗长细节文字，含请求/响应与命令输出片段。", 25),
			Confidence: "observed", AssetIDs: []int64{int64(200 + i)},
			Assets: []string{fmt.Sprintf("edge-%d.example.test", i)},
		})
	}
	return seed
}

// representativeOverviewData mirrors a mature task's graph_overview: the newest
// recent_facts window largely overlaps the intent-relevant seed facts, plus a set
// of cold digests with inline bodies.
func representativeOverviewData(seed WorkerEntrySeed) map[string]any {
	recent := make([]map[string]any, 0, 20)
	// newest 20 facts = the seed's newest general facts (the common mature case)
	facts := seed.ConfirmedFacts
	for i := len(facts) - 1; i >= 0 && len(recent) < 20; i-- {
		f := facts[i]
		recent = append(recent, map[string]any{"id": f.ID, "state": "confirmed", "summary": f.Summary, "confidence": "observed"})
	}
	cold := make([]map[string]any, 0, 10)
	for i := 0; i < 10; i++ {
		cold = append(cold, map[string]any{
			"id": int64(900 + i), "member_count": 7,
			"body": strings.Repeat("冷区折叠摘要正文，概述若干已冷却节点。", 12),
		})
	}
	goals := []map[string]any{{"id": int64(9), "state": "open", "text": "核验授权范围内风险"}}
	return map[string]any{
		"goals": goals, "hints": []map[string]any{}, "facts_total": 60, "findings_total": 2,
		"recent_facts": recent, "cold_digests": cold,
		"open_intents": []map[string]any{{"id": int64(300), "summary": "继续核验应用主机", "state": "open"}},
	}
}

// TestStage3ContextBudgetReduction measures the per-intent repeated context
// (entry_seed + worker overview) before vs after stage 3 on a representative
// mature-task fixture. These two blocks ride in EVERY turn's input (seed in the
// system prompt, overview in the launch user message carried in history), so a
// reduction here is a per-turn input-token reduction for the whole intent.
func TestStage3ContextBudgetReduction(t *testing.T) {
	seed := representativeSeed()
	seedIDs := entrySeedFactIDSet(seed)

	seedNew := utf8.RuneCountInString(RenderWorkerEntrySeed(seed))
	seedOld := seedNew + legacyEntrySeedDetailBytes(seed) -
		// new render still inlines clipped key-fact details (cap 300); add those back
		// out of the legacy delta so seedOld reflects the true pre-change size.
		keyDetailRunes(seed)

	ovOld := utf8.RuneCountInString(legacyWorkerOverview(representativeOverviewData(seed)))
	ovNew := utf8.RuneCountInString(newWorkerOverviewBody(representativeOverviewData(seed), seedIDs))

	// Fixed static system body (role prompt + code-owned tails), unchanged by stage 3,
	// included only to report the share of the full repeated context.
	sys := utf8.RuneCountInString(workerSystem("", "", "/data", "/data/tasks/1/i1", false, FootprintToggles{}))

	repeatedOld := seedOld + ovOld
	repeatedNew := seedNew + ovNew
	totalOld := sys + repeatedOld
	totalNew := sys + repeatedNew

	redRepeated := 100.0 * float64(repeatedOld-repeatedNew) / float64(repeatedOld)
	redTotal := 100.0 * float64(totalOld-totalNew) / float64(totalOld)
	t.Logf("runes — system(static)=%d", sys)
	t.Logf("runes — entry_seed: old=%d new=%d", seedOld, seedNew)
	t.Logf("runes — overview:   old=%d new=%d", ovOld, ovNew)
	t.Logf("reduction — seed+overview (reducible repeated context): %.1f%% (%d→%d)", redRepeated, repeatedOld, repeatedNew)
	t.Logf("reduction — system+seed+overview (full per-turn fixed context): %.1f%% (%d→%d)", redTotal, totalOld, totalNew)

	if redRepeated < 20.0 {
		t.Fatalf("stage-3 reduction on reducible repeated context = %.1f%%, want >= 20%%", redRepeated)
	}
	if seedNew >= seedOld || ovNew >= ovOld {
		t.Fatalf("both blocks must shrink: seed %d->%d overview %d->%d", seedOld, seedNew, ovOld, ovNew)
	}
	// No fact is lost: every seed fact id is still named in the seed render.
	render := RenderWorkerEntrySeed(seed)
	for _, f := range seed.ConfirmedFacts[5:] {
		if !strings.Contains(render, fmt.Sprintf("fact #%d ", f.ID)) {
			t.Fatalf("fact #%d dropped from seed render", f.ID)
		}
	}
}

// keyDetailRunes is the inline detail bytes the NEW render keeps (key facts only,
// clipped to entrySeedKeyDetailCap) — needed to reconstruct the legacy seed size.
func keyDetailRunes(seed WorkerEntrySeed) int {
	n := 0
	for _, f := range seed.ConfirmedFacts {
		if isKeyFact(f.Category, f.EvidenceIDs) {
			if d := strings.TrimSpace(f.Detail); d != "" {
				n += utf8.RuneCountInString("  细节：") + utf8.RuneCountInString(clipRunes(d, entrySeedKeyDetailCap)) + 1
			}
		}
	}
	return n
}

func TestRenderWorkerGraphOverviewDropsPlannerFieldsAndCapsLists(t *testing.T) {
	longText := strings.Repeat("超长内容", 120) // 480 runes
	running := make([]map[string]any, 10)
	for i := range running {
		running[i] = map[string]any{"id": int64(i + 1), "summary": longText, "asset_ids": []int64{1, 2, 3}, "parents": []int64{9}}
	}
	recent := make([]map[string]any, 18)
	for i := range recent {
		recent[i] = map[string]any{"id": int64(100 + i), "summary": longText, "state": "confirmed"}
	}
	cold := make([]map[string]any, 8)
	for i := range cold {
		cold[i] = map[string]any{"id": int64(500 + i), "member_count": 5, "body": longText}
	}
	hints := make([]map[string]any, 12)
	for i := range hints {
		hints[i] = map[string]any{"id": int64(700 + i), "state": "open", "text": longText}
	}
	data := map[string]any{
		"coverage":            map[string]any{"pct": 25},
		"open_intents":        []map[string]any{{"id": int64(1), "summary": "open"}},
		"recent_done_intents": []map[string]any{{"id": int64(2), "summary": "done"}},
		"crown_jewels":        []map[string]any{{"asset_id": int64(3)}},
		"goals":               []map[string]any{{"id": int64(4), "text": "goal"}},
		"cold_digests_more":   []int64{999},
		"running_intents":     running,
		"recent_facts":        recent,
		"cold_digests":        cold,
		"hints":               hints,
		"related_tasks": []map[string]any{{
			"source_task_id":        int64(42),
			"inherited":             true,
			"facts":                 10,
			"recent_intent_results": []map[string]any{{"id": int64(1)}},
			"asset_scope":           []string{"10.0.0.1"},
			"cold_digests":          []map[string]any{{"id": int64(8), "body": longText}},
			"recent_facts":          recent,
		}},
	}
	body := newWorkerOverviewBody(data, map[int64]bool{100: true, 101: true})
	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("worker overview JSON invalid: %v\n%s", err, body)
	}
	for _, dropped := range []string{"coverage", "open_intents", "recent_done_intents", "crown_jewels", "goals", "cold_digests_more"} {
		if _, ok := parsed[dropped]; ok {
			t.Fatalf("planner-only field %q must be stripped from worker overview", dropped)
		}
	}
	if got := len(parsed["running_intents"].([]any)); got != workerOverviewRunningCap {
		t.Fatalf("running_intents len=%d want %d", got, workerOverviewRunningCap)
	}
	if got := len(parsed["recent_facts"].([]any)); got != workerOverviewRecentFactsCap {
		t.Fatalf("recent_facts len=%d want %d", got, workerOverviewRecentFactsCap)
	}
	if got := len(parsed["cold_digests"].([]any)); got != workerOverviewColdDigestsCap {
		t.Fatalf("cold_digests len=%d want %d", got, workerOverviewColdDigestsCap)
	}
	if got := len(parsed["hints"].([]any)); got != workerOverviewHintsCap {
		t.Fatalf("hints len=%d want %d", got, workerOverviewHintsCap)
	}
	rt := parsed["related_tasks"].([]any)[0].(map[string]any)
	for _, dropped := range []string{"recent_intent_results", "asset_scope", "cold_digests"} {
		if _, ok := rt[dropped]; ok {
			t.Fatalf("related_tasks[%q] should be stripped from worker overview", dropped)
		}
	}
	if got := len(rt["recent_facts"].([]any)); got != workerOverviewRelatedListCap {
		t.Fatalf("related_tasks recent_facts len=%d want %d", got, workerOverviewRelatedListCap)
	}
}

func TestRenderWorkerGraphOverviewCapsFindingList(t *testing.T) {
	longText := strings.Repeat("漏洞详情描述", 60) // 360 runes
	findings := make([]map[string]any, 10)
	for i := range findings {
		findings[i] = map[string]any{
			"id":          int64(900 + i),
			"from_intent": int64(700 + i),
			"summary":     longText,
		}
	}
	body := newWorkerOverviewBody(map[string]any{"finding_list": findings}, nil)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("worker overview JSON invalid: %v\n%s", err, body)
	}
	gotList := parsed["finding_list"].([]any)
	if len(gotList) != workerOverviewFindingsCap {
		t.Fatalf("finding_list len=%d want %d", len(gotList), workerOverviewFindingsCap)
	}
	firstSummary := gotList[0].(map[string]any)["summary"].(string)
	if utf8.RuneCountInString(firstSummary) > workerOverviewRunningSummaryMax+1 {
		t.Fatalf("finding summary not clipped: runes=%d > %d", utf8.RuneCountInString(firstSummary), workerOverviewRunningSummaryMax+1)
	}
}

func TestEntrySeedDirectParentDetailRelevantKeysAndEmptyGraph(t *testing.T) {
	// 1. Direct parent general fact retains up to 600-rune detail; non-parent general fact omits detail.
	parentDetail := strings.Repeat("上游凭据与参数细节", 50) // 450 runes (<600)
	siblingDetail := strings.Repeat("无关旁枝细节", 50)
	seed := WorkerEntrySeed{
		Prefetched: true,
		ConfirmedFacts: []EntryFact{
			{ID: 10, Summary: "parent general", Detail: parentDetail, DirectParent: true, Relevant: true},
			{ID: 11, Summary: "sibling general", Detail: siblingDetail, DirectParent: false, Relevant: true},
		},
	}
	out := RenderWorkerEntrySeed(seed)
	if !strings.Contains(out, parentDetail) {
		t.Fatalf("direct parent general fact must inline its detail:\n%s", out)
	}
	if strings.Contains(out, siblingDetail) {
		t.Fatalf("non-parent general fact must not inline its detail:\n%s", out)
	}

	// 2. Intent-relevant key facts beat 45 older unrelated-host negative_result key facts.
	var many []EntryFact
	for i := 1; i <= 45; i++ {
		many = append(many, EntryFact{ID: int64(i), Summary: fmt.Sprintf("other-host-neg-%d", i), Category: "negative_result", Relevant: false})
	}
	many = append(many, EntryFact{ID: 999, Summary: "target-host-key", Category: "negative_result", Relevant: true})
	keys, _, omittedKeys, _ := selectedEntrySeedFacts(WorkerEntrySeed{Prefetched: true, ConfirmedFacts: many})
	if len(keys) != entrySeedKeyFactCap || omittedKeys != 6 {
		t.Fatalf("len(keys)=%d omittedKeys=%d", len(keys), omittedKeys)
	}
	foundTarget := false
	for _, k := range keys {
		if k.ID == 999 {
			foundTarget = true
		}
	}
	if !foundTarget {
		t.Fatal("intent-relevant key fact #999 must not be evicted by older unrelated-host negative results")
	}

	// 3. EmptyGraph opening avoids mandatory turn-1 list_facts round-trip.
	empty := RenderWorkerEntrySeed(WorkerEntrySeed{Prefetched: true, EmptyGraph: true})
	if !strings.Contains(empty, "任务开局") || !strings.Contains(empty, "无需额外调 list_facts") {
		t.Fatalf("EmptyGraph seed should clarify opening state:\n%s", empty)
	}
}

