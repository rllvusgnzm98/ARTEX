package agent

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// GraphIncompleteMarker is the fail-soft signal injected when graph compression
// or entry prefetch fails. It must be unmistakable in the worker prompt; entry
// is not blocked, and the failure must not be written as a target/goal failure.
const GraphIncompleteMarker = "图谱不完整"

// WorkerEntrySeed is the graph context pre-injected at worker claim/entry.
// Prefetch itself is the graph read: when it succeeds, a subsequent worker
// does not need to open with a scan to learn what prior workers already wrote.
type WorkerEntrySeed struct {
	ConfirmedFacts    []EntryFact
	NextHops          []EntryTarget
	GraphIncomplete   bool
	IncompleteReasons []string
	Prefetched        bool
	// EmptyGraph is true when prefetch succeeded cleanly and the exploration
	// graph currently has zero confirmed facts (fresh opening). In that state
	// the worker does not need to spend turn 1 calling list_facts.
	EmptyGraph bool
	// Writes is always empty when produced by LoadWorkerEntrySeed / BuildWorkerEntrySeed:
	// prefetch is read-only. Tests assert this so a prefetch failure cannot be
	// recorded as a target/goal failure.
	Writes []string
}

// EntryFact is a relevant confirmed fact or a task-wide key observation.
type EntryFact struct {
	ID            int64
	Summary       string
	Detail        string
	Confidence    string
	Category      string
	EvidenceIDs   []string
	ArtifactPaths []string
	AssetIDs      []int64
	Assets        []string
	FromIntent    int64
	DirectParent  bool // true when directly linked via derived_from to the claimed intent
	Relevant      bool // true when linked via intent lineage or asset anchors (vs unrelated-host key fact)
}

// EntryTarget is a target confirmed reachable by a prior fact but not yet
// delivered (no finding, no met goal proved against it). It must be continued
// as the next hop, not reopened as a brand-new target.
type EntryTarget struct {
	AssetID      int64
	Label        string
	FactIDs      []int64
	Continuation bool
}

// EntryGraph is the in-memory snapshot BuildWorkerEntrySeed reads. Tests build
// this directly (no database) with a multi-host, multi-stage fixture.
type EntryGraph struct {
	Intent         *db.Node
	IntentAssetIDs []int64
	Facts          []*db.Node
	Findings       []*db.Node
	Goals          []*db.Node
	Edges          []db.Edge
	Anchors        map[int64][]int64 // node id → asset ids
	Assets         map[int64]string  // asset id → stable label
	AssetTypes     map[int64]string  // asset id → asset type (ip/subdomain/service/...)
	CompressErr    error
	PrefetchErr    error
}

// IsGraphReadTool reports whether a tool is a graph/context read (not a probe).
func IsGraphReadTool(name string) bool {
	switch name {
	case "list_facts", "list_companies", "list_assets", "list_findings",
		"node_detail", "graph_overview", "get_worker_trace", "search_all_worker_traces",
		"asset_neighbors":
		return true
	default:
		return false
	}
}

// IsSideEffectTool reports whether a tool may probe or mutate the environment
// or write to the graph. Used to lock "read happens before the first side effect".
func IsSideEffectTool(name string) bool {
	switch name {
	case "Bash", "Write", "Edit", "MultiEdit", "WebFetch", "web_search",
		"record_fact", "report_finding", "insert_assets", "add_finding",
		"add_company_scope", "add_task_scope", "set_goals", "set_constraints",
		"prove_goal", "goal_met", "register_session", "session_recon",
		"tunnel_deploy", "tunnel_teardown",
		"add_credential":
		return true
	default:
		return false
	}
}

// GraphReadBeforeSideEffect is the regression lock for the entry hard step.
// A successful prefetch counts as the graph read. Otherwise a graph-read tool
// must appear in calls before the first side-effect tool.
func GraphReadBeforeSideEffect(seed WorkerEntrySeed, toolCalls []string) bool {
	if seed.Prefetched && !seed.GraphIncomplete {
		return true
	}
	if seed.Prefetched && len(seed.ConfirmedFacts) > 0 {
		return true
	}
	seenRead := seed.Prefetched && !seed.GraphIncomplete
	for _, name := range toolCalls {
		if IsGraphReadTool(name) {
			seenRead = true
			continue
		}
		if IsSideEffectTool(name) {
			return seenRead
		}
	}
	return seenRead || seed.Prefetched
}

// RepeatScanRisk counts already-confirmed-reachable targets a later worker
// would treat as needing a fresh probe. With a completed read-side seed those
// targets are already listed, so the count drops relative to a no-read contrast
// (empty seed) on the same neighborhood.
func RepeatScanRisk(seed WorkerEntrySeed, confirmedAssetIDs []int64) int {
	known := map[int64]bool{}
	for _, f := range seed.ConfirmedFacts {
		if isKeyFact(f.Category, f.EvidenceIDs) {
			continue
		}
		for _, id := range f.AssetIDs {
			known[id] = true
		}
	}
	for _, h := range seed.NextHops {
		known[h.AssetID] = true
	}
	n := 0
	for _, id := range uniqueIDs(confirmedAssetIDs) {
		if id <= 0 {
			continue
		}
		if !known[id] {
			n++
		}
	}
	return n
}

// BuildWorkerEntrySeed projects a graph snapshot into the entry pre-seed.
// It never writes; compress/prefetch errors fail soft and set GraphIncomplete.
func BuildWorkerEntrySeed(g EntryGraph) WorkerEntrySeed {
	seed := WorkerEntrySeed{Prefetched: g.PrefetchErr == nil}
	if g.CompressErr != nil {
		seed.GraphIncomplete = true
		seed.IncompleteReasons = append(seed.IncompleteReasons, "graph_compress")
	}
	if g.PrefetchErr != nil {
		seed.GraphIncomplete = true
		seed.IncompleteReasons = append(seed.IncompleteReasons, "prefetch")
		seed.Prefetched = false
	}

	if g.Intent == nil {
		return seed
	}

	parentFacts := map[int64]bool{}
	yieldsOf := map[int64][]int64{}
	producedBy := map[int64]int64{}
	provesGoal := map[int64][]int64{} // evidence node → goal ids
	for _, e := range g.Edges {
		switch e.Rel {
		case db.RelDerivedFrom:
			if e.To == g.Intent.ID {
				parentFacts[e.From] = true
			}
		case db.RelYields:
			yieldsOf[e.From] = append(yieldsOf[e.From], e.To)
			producedBy[e.To] = e.From
		case db.RelProves:
			provesGoal[e.From] = append(provesGoal[e.From], e.To)
		}
	}

	producerIntents := map[int64]bool{}
	for fid := range parentFacts {
		if intentID := producedBy[fid]; intentID > 0 {
			producerIntents[intentID] = true
		}
	}
	siblingFacts := map[int64]bool{}
	for intentID := range producerIntents {
		for _, id := range yieldsOf[intentID] {
			siblingFacts[id] = true
		}
	}

	intentAssets := uniqueIDs(append([]int64(nil), g.IntentAssetIDs...))
	inferredIntentAssets := false
	if len(intentAssets) == 0 && len(parentFacts) == 0 && g.Intent != nil && len(g.Assets) > 0 {
		intentAssets = inferIntentAssetIDs(string(g.Intent.Payload), g.Assets)
		inferredIntentAssets = true
	}
	anchorOf := func(id int64) []int64 {
		if g.Anchors == nil {
			return nil
		}
		return g.Anchors[id]
	}

	metGoals := map[int64]bool{}
	for _, goal := range g.Goals {
		if goal != nil && goal.State == "met" {
			metGoals[goal.ID] = true
		}
	}
	delivered := map[int64]bool{}
	for _, n := range g.Findings {
		if n == nil {
			continue
		}
		for _, a := range anchorOf(n.ID) {
			delivered[a] = true
		}
	}
	for ev, goals := range provesGoal {
		for _, gid := range goals {
			if !metGoals[gid] {
				continue
			}
			for _, a := range anchorOf(ev) {
				delivered[a] = true
			}
		}
	}

	type factView struct {
		node          *db.Node
		summary       string
		detail        string
		confidence    string
		category      string
		evidenceIDs   []string
		artifactPaths []string
		assets        []int64
		from          int64
	}
	var confirmed []factView
	byID := map[int64]factView{}
	for _, n := range g.Facts {
		if n == nil || n.State == db.StateOrigin {
			continue
		}
		summary, detail, conf := factFields(n)
		category, evidenceIDs := factPriorityFields(n)
		artifactPaths := factArtifactPaths(n)
		key := isKeyFact(category, evidenceIDs)
		if key && n.State != "confirmed" || !key && !isConfirmedFact(n.State, conf) {
			continue
		}
		fv := factView{
			node:          n,
			summary:       summary,
			detail:        detail,
			confidence:    conf,
			category:      category,
			evidenceIDs:   evidenceIDs,
			artifactPaths: artifactPaths,
			assets:        uniqueIDs(anchorOf(n.ID)),
			from:          producedBy[n.ID],
		}
		confirmed = append(confirmed, fv)
		byID[n.ID] = fv
	}

	seed.EmptyGraph = g.PrefetchErr == nil && !seed.GraphIncomplete && len(confirmed) == 0

	ipNonIPPeers := map[int64]map[int64]bool{}
	collectPeers := func(ids []int64) {
		var ips, nonIPs []int64
		for _, id := range uniqueIDs(ids) {
			if isBareIPAsset(g, id) {
				ips = append(ips, id)
			} else {
				nonIPs = append(nonIPs, id)
			}
		}
		for _, ipID := range ips {
			if ipNonIPPeers[ipID] == nil {
				ipNonIPPeers[ipID] = map[int64]bool{}
			}
			for _, nid := range nonIPs {
				ipNonIPPeers[ipID][nid] = true
			}
		}
	}
	for _, fv := range confirmed {
		collectPeers(fv.assets)
	}
	for _, ids := range g.Anchors {
		collectPeers(ids)
	}
	sharedIPs := map[int64]bool{}
	for ipID, peers := range ipNonIPPeers {
		if len(peers) >= 2 {
			sharedIPs[ipID] = true
		}
	}

	explicitIntentIPs := map[int64]bool{}
	for _, id := range uniqueIDs(g.IntentAssetIDs) {
		if isBareIPAsset(g, id) {
			explicitIntentIPs[id] = true
		}
	}
	hasNonIPTarget := false
	for _, id := range intentAssets {
		if !isBareIPAsset(g, id) {
			hasNonIPTarget = true
			break
		}
	}
	if !hasNonIPTarget {
		for fid := range parentFacts {
			for _, id := range byID[fid].assets {
				if !isBareIPAsset(g, id) {
					hasNonIPTarget = true
					break
				}
			}
			if hasNonIPTarget {
				break
			}
		}
	}
	// If intent_assets were inferred from text and already resolved non-IP hosts
	// (e.g. "pay.acme.test (104.18.0.1)"), drop bare IP tokens from fallback matching
	// so CDN/shared ingress IPs never cross-match sibling virtual hosts.
	if inferredIntentAssets && hasNonIPTarget {
		filtered := intentAssets[:0]
		for _, id := range intentAssets {
			if !isBareIPAsset(g, id) {
				filtered = append(filtered, id)
			}
		}
		intentAssets = filtered
	}

	relevant := map[int64]bool{}
	intentRelevant := map[int64]bool{}
	seedAnchors := map[int64]bool{}
	mark := func(id int64, isIntentRelevant bool) {
		fv, ok := byID[id]
		if !ok {
			return
		}
		if isIntentRelevant {
			intentRelevant[id] = true
		}
		if relevant[id] {
			return
		}
		relevant[id] = true
		if isKeyFact(fv.category, fv.evidenceIDs) {
			return
		}
		for _, a := range fv.assets {
			seedAnchors[a] = true
		}
	}
	for id := range parentFacts {
		mark(id, true)
	}
	for id := range siblingFacts {
		mark(id, true)
	}
	for _, fv := range confirmed {
		if overlapsID(fv.assets, intentAssets) {
			mark(fv.node.ID, true)
		}
	}
	// One expansion: confirmed facts that share an anchor with the seed set
	// (prior-stage observations on a host this hop is continuing from).
	// Isolate bare IPs that are shared across multiple VHosts (e.g. CDN/ALB) or
	// collateral to a non-IP target unless the caller explicitly anchored that bare IP.
	expandAnchors := map[int64]bool{}
	for a := range seedAnchors {
		if isBareIPAsset(g, a) && (hasNonIPTarget || sharedIPs[a]) && !explicitIntentIPs[a] {
			continue
		}
		expandAnchors[a] = true
	}
	intentAssetSet := map[int64]bool{}
	for _, id := range intentAssets {
		intentAssetSet[id] = true
	}
	for _, fv := range confirmed {
		if !overlapsSet(fv.assets, expandAnchors) {
			continue
		}
		if hasNonIPTarget {
			var fvNonIPs []int64
			for _, id := range fv.assets {
				if !isBareIPAsset(g, id) {
					fvNonIPs = append(fvNonIPs, id)
				}
			}
			// If fv carries non-IP hosts (e.g. sibling VHost + shared IP), require
			// at least one non-IP overlap so a shared IP never bridges unrelated VHosts.
			if len(fvNonIPs) > 0 && !overlapsSet(fvNonIPs, expandAnchors) && !overlapsSet(fvNonIPs, intentAssetSet) {
				continue
			}
		}
		mark(fv.node.ID, true)
	}
	// Task-wide key facts: scope_limit (authorizations/global constraints) or
	// unanchored task-root key facts (fromIntent==0) apply globally across all
	// workers. Worker-yielded per-target cleanup_status / negative_result / evidence
	// stay scoped to their lineage (parentFacts/siblingFacts) or anchored hosts.
	for _, fv := range confirmed {
		if isTaskGlobalKeyFact(fv.category, fv.evidenceIDs, fv.assets, fv.from) {
			mark(fv.node.ID, false)
		}
	}

	var facts []EntryFact
	for _, fv := range confirmed {
		if !relevant[fv.node.ID] {
			continue
		}
		labels := make([]string, 0, len(fv.assets))
		for _, a := range fv.assets {
			labels = append(labels, assetLabelOf(g.Assets, a))
		}
		facts = append(facts, EntryFact{
			ID:            fv.node.ID,
			Summary:       fv.summary,
			Detail:        fv.detail,
			Confidence:    fv.confidence,
			Category:      fv.category,
			EvidenceIDs:   fv.evidenceIDs,
			ArtifactPaths: fv.artifactPaths,
			AssetIDs:      fv.assets,
			Assets:        labels,
			FromIntent:    fv.from,
			DirectParent:  parentFacts[fv.node.ID],
			Relevant:      intentRelevant[fv.node.ID],
		})
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].ID < facts[j].ID })
	seed.ConfirmedFacts = facts

	// Neighborhood of confirmed-reachable assets, minus those already delivered.
	factIDsFor := map[int64][]int64{}
	for _, f := range facts {
		if isKeyFact(f.Category, f.EvidenceIDs) {
			continue
		}
		for _, a := range f.AssetIDs {
			factIDsFor[a] = append(factIDsFor[a], f.ID)
		}
	}
	intentSet := map[int64]bool{}
	for _, a := range intentAssets {
		intentSet[a] = true
	}
	var hops []EntryTarget
	for a := range seedAnchors {
		if delivered[a] {
			continue
		}
		if isBareIPAsset(g, a) && (hasNonIPTarget || sharedIPs[a]) && !explicitIntentIPs[a] {
			continue
		}
		hops = append(hops, EntryTarget{
			AssetID:      a,
			Label:        assetLabelOf(g.Assets, a),
			FactIDs:      uniqueIDs(factIDsFor[a]),
			Continuation: intentSet[a] || len(factIDsFor[a]) > 0,
		})
	}
	sort.Slice(hops, func(i, j int) bool {
		if hops[i].Continuation != hops[j].Continuation {
			return hops[i].Continuation
		}
		return hops[i].AssetID < hops[j].AssetID
	})
	seed.NextHops = hops
	return seed
}

// Entry-seed render caps: a long-running task can accumulate many relevant
// confirmed facts with long details; the rest stay one list_facts call away.
const (
	entrySeedFactCap    = 60
	entrySeedKeyFactCap = 40
	// 阶段三(上下文控制)：关键事实(否定结果/范围限制/清理状态/带证据)保留内联细节但裁剪；
	// 本意图的直接上游父事实(derived_from)保留更多细节(最多 8 条 × 600 字)，避免 worker
	// 进场后反复调 node_detail 回查上游参数/凭据/路径；其余普通事实只给摘要。
	entrySeedKeyDetailCap         = 300
	entrySeedParentDetailCap      = 600
	entrySeedParentDetailCountCap = 8
)

func clipRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…（已截断，完整见 node_detail）"
}

// RenderWorkerEntrySeed formats the pre-seed, incomplete-graph marker, and
// entry hard-step for the worker system prompt. Always fail-soft: an incomplete
// graph still returns a prompt block and never a hard error.
func RenderWorkerEntrySeed(seed WorkerEntrySeed) string {
	var b strings.Builder
	if seed.GraphIncomplete {
		reason := strings.Join(seed.IncompleteReasons, ",")
		if reason == "" {
			reason = "unknown"
		}
		fmt.Fprintf(&b, "\n\n【%s】预取或图谱压缩失败（原因：%s）。以下内容可能不完整，进场不被阻断；不要把这次失败记录为目标失败，也不要假装图谱仍完整。\n",
			GraphIncompleteMarker, reason)
	}

	b.WriteString("\n\n【进场硬步骤】领取意图后，第一次工具调用必须是读图（list_facts，或 list_companies / node_detail 等只读查图工具）。")
	b.WriteString("下面若已预塞相关已确认事实，视为读图已发生，不要对已确认可达的目标再开一轮扫描。")
	b.WriteString("禁止把已确认可达但未兑现的目标当成新目标重开，应作为下一跳接着做。")
	b.WriteString("关键事实中的否定结果、范围限制、清理状态及 inferred 推断不代表目标已确认可达，也不构成扩大授权范围的许可。")
	if seed.GraphIncomplete {
		b.WriteString("若出现「" + GraphIncompleteMarker + "」，先用只读工具把能读到的补上，再行动。")
	}

	if len(seed.ConfirmedFacts) == 0 {
		if seed.EmptyGraph {
			b.WriteString("\n\n【进场预塞】当前探索图尚无已确认事实（任务开局），视为读图已完成；无需额外调 list_facts 空查，可直接围绕本意图开展探测。")
		} else if seed.Prefetched && !seed.GraphIncomplete {
			b.WriteString("\n\n【进场预塞】暂无与本意图直接关联的已确认事实或关键限制/证据；如需查看全局其他分支结论，可按需调 list_facts / node_detail。")
		} else {
			b.WriteString("\n\n【进场预塞】没有相关事实或关键限制/证据。第一次工具仍须先读图（list_facts）。")
		}
		return b.String()
	}

	b.WriteString("\n\n【进场预塞：相关事实与任务关键限制/证据】\n")
	fmt.Fprintf(&b, "关键事实优先（最多 %d 条，本意图相关与范围/清理限制优先）；其余位置补最新相关普通事实，总计最多 %d 条。\n", entrySeedKeyFactCap, entrySeedFactCap)
	b.WriteString("上游直接父事实与关键事实保留裁剪后的细节；其余普通事实只列摘要（含 evidence_ids、资产、来源意图），完整细节按需用 node_detail 查。\n")
	keys, general, omittedKeys, omittedGeneral := selectedEntrySeedFacts(seed)
	if omittedKeys+omittedGeneral > 0 {
		fmt.Fprintf(&b, "（另有 %d 条事实未列出：关键事实 %d 条，相关普通事实 %d 条；需要时用 list_facts / node_detail 查）\n", omittedKeys+omittedGeneral, omittedKeys, omittedGeneral)
	}
	facts := append(keys, general...)
	inlineParents := map[int64]bool{}
	var parentIDs []int64
	for _, f := range facts {
		if f.DirectParent && strings.TrimSpace(f.Detail) != "" {
			parentIDs = append(parentIDs, f.ID)
		}
	}
	sort.Slice(parentIDs, func(i, j int) bool { return parentIDs[i] < parentIDs[j] })
	if len(parentIDs) > entrySeedParentDetailCountCap {
		parentIDs = parentIDs[len(parentIDs)-entrySeedParentDetailCountCap:]
	}
	for _, id := range parentIDs {
		inlineParents[id] = true
	}
	for _, f := range facts {
		conf := f.Confidence
		if conf == "" {
			conf = "confirmed"
		}
		fmt.Fprintf(&b, "- fact #%d (%s)：%s", f.ID, conf, strings.TrimSpace(f.Summary))
		category := f.Category
		if category == "" {
			category = "general"
		}
		fmt.Fprintf(&b, " [category=%s]", category)
		if len(f.EvidenceIDs) > 0 {
			refs, _ := json.Marshal(f.EvidenceIDs)
			fmt.Fprintf(&b, " [evidence_ids=%s]", refs)
		}
		if len(f.ArtifactPaths) > 0 {
			fmt.Fprintf(&b, " [artifact_paths=%s]", strings.Join(f.ArtifactPaths, "；"))
		}
		if len(f.Assets) > 0 {
			fmt.Fprintf(&b, "（资产：%s）", strings.Join(f.Assets, "、"))
		}
		if f.FromIntent > 0 {
			fmt.Fprintf(&b, "［来自意图 #%d］", f.FromIntent)
		}
		b.WriteByte('\n')
		// 阶段三+优化：本意图直接上游父事实（derived_from，最多最新 8 条）保留最多 600 字细节，
		// 减少 worker 开局反复调 node_detail 回查上游线索；关键事实保留 300 字细节；
		// 其余普通事实仅给摘要，按需 node_detail 回查。
		if d := strings.TrimSpace(f.Detail); d != "" {
			switch {
			case inlineParents[f.ID]:
				fmt.Fprintf(&b, "  细节：%s\n", clipRunes(d, entrySeedParentDetailCap))
			case isKeyFact(f.Category, f.EvidenceIDs):
				fmt.Fprintf(&b, "  细节：%s\n", clipRunes(d, entrySeedKeyDetailCap))
			}
		}
	}

	if len(seed.NextHops) > 0 {
		b.WriteString("\n【已确认可达但未兑现的目标（下一跳接着打，不是新开）】\n")
		for _, h := range seed.NextHops {
			label := h.Label
			if label == "" {
				label = fmt.Sprintf("asset#%d", h.AssetID)
			}
			factNote := ""
			if len(h.FactIDs) > 0 {
				ids := make([]string, len(h.FactIDs))
				for i, id := range h.FactIDs {
					ids[i] = fmt.Sprintf("#%d", id)
				}
				factNote = "由事实 " + strings.Join(ids, "、") + " 确认可达，"
			}
			fmt.Fprintf(&b, "- %s（%s尚无对应已兑现结果，作为下一跳接着做，不要当新目标重开）\n", label, factNote)
		}
	}
	return b.String()
}

// graphIncompleteReader is the first-class compaction-failure signal
// LoadWorkerEntrySeed reads. ExplorationStore implements it.
type graphIncompleteReader interface {
	GraphIncompleteReason() (string, error)
}

// attachStoredGraphIncomplete reads the first-class compaction-failure signal
// written after empty-response retries are exhausted, and sets CompressErr so
// BuildWorkerEntrySeed / RenderWorkerEntrySeed reuse the existing
// 【图谱不完整】 marker. It does not invent a second flag or wording.
func attachStoredGraphIncomplete(g *EntryGraph, src graphIncompleteReader) {
	if g == nil || g.CompressErr != nil || src == nil {
		return
	}
	reason, err := src.GraphIncompleteReason()
	if err != nil {
		g.CompressErr = err
		return
	}
	if strings.TrimSpace(reason) != "" {
		g.CompressErr = fmt.Errorf("%s", strings.TrimSpace(reason))
	}
}

// LoadWorkerEntrySeed prefetches the exploration graph for a claimed intent.
// Compression and listing errors fail soft. This function only reads.
func LoadWorkerEntrySeed(ts *db.ExplorationStore, as *db.AssetStore, intent *db.Node) WorkerEntrySeed {
	return loadWorkerEntrySeedFrom(ts, newGraphSnapshot(ts), as, intent)
}

// loadWorkerEntrySeedFrom is LoadWorkerEntrySeed reading through a shared snapshot.
func loadWorkerEntrySeedFrom(ts *db.ExplorationStore, snap *graphSnapshot, as *db.AssetStore, intent *db.Node) WorkerEntrySeed {
	g := EntryGraph{Intent: intent, Anchors: map[int64][]int64{}, Assets: map[int64]string{}, AssetTypes: map[int64]string{}}
	if intent != nil {
		g.IntentAssetIDs = intentAssetIDs(intent)
	}
	if ts == nil {
		g.PrefetchErr = fmt.Errorf("exploration store missing")
		return BuildWorkerEntrySeed(g)
	}

	if _, err := snap.coldGraph(); err != nil {
		g.CompressErr = err
	}
	attachStoredGraphIncomplete(&g, ts)

	var prefetchErr error
	collect := func(err error) {
		if err != nil && prefetchErr == nil {
			prefetchErr = err
		}
	}

	keys, err := ts.EntrySeedFacts(true)
	collect(err)
	general, err := ts.EntrySeedFacts(false)
	collect(err)
	facts := append(keys, general...)
	g.Facts = facts
	findings, err := snap.listByKind(db.KindFinding, 1000)
	collect(err)
	g.Findings = findings
	goals, err := snap.listByKind(db.KindGoal, 200)
	collect(err)
	g.Goals = goals
	edges, err := snap.edgeList(5000)
	collect(err)
	g.Edges = edges

	var nodeIDs []int64
	for _, n := range facts {
		if n != nil {
			nodeIDs = append(nodeIDs, n.ID)
		}
	}
	for _, n := range findings {
		if n != nil {
			nodeIDs = append(nodeIDs, n.ID)
		}
	}
	if intent != nil {
		nodeIDs = append(nodeIDs, intent.ID)
	}
	anchors, err := ts.NodeAssets(nodeIDs)
	collect(err)
	if anchors != nil {
		g.Anchors = anchors
	}

	assetIDs := append([]int64(nil), g.IntentAssetIDs...)
	for _, ids := range g.Anchors {
		assetIDs = append(assetIDs, ids...)
	}
	assetIDs = uniqueIDs(assetIDs)
	if as != nil && len(assetIDs) > 0 {
		assets, err := as.GetByIDs(assetIDs)
		collect(err)
		for _, a := range assets {
			if a != nil {
				g.Assets[a.ID] = describeAsset(a)
				g.AssetTypes[a.ID] = a.Type
			}
		}
	}
	g.PrefetchErr = prefetchErr
	return BuildWorkerEntrySeed(g)
}

func isConfirmedFact(state, confidence string) bool {
	c := strings.ToLower(strings.TrimSpace(confidence))
	if c == "inferred" {
		return false
	}
	if c == "observed" {
		return true
	}
	return state == "confirmed"
}

func factFields(n *db.Node) (summary, detail, confidence string) {
	if n == nil {
		return "", "", ""
	}
	var p map[string]any
	_ = json.Unmarshal(n.Payload, &p)
	summary, _ = p["summary"].(string)
	if summary == "" {
		summary, _ = p["text"].(string)
	}
	detail, _ = p["detail"].(string)
	confidence, _ = p["confidence"].(string)
	return
}

func factPriorityFields(n *db.Node) (category string, evidenceIDs []string) {
	var p struct {
		Category    string   `json:"category"`
		EvidenceIDs []string `json:"evidence_ids"`
	}
	_ = json.Unmarshal(n.Payload, &p)
	return p.Category, p.EvidenceIDs
}

func factArtifactPaths(n *db.Node) []string {
	if n == nil {
		return nil
	}
	var p struct {
		ArtifactPaths []string `json:"artifact_paths"`
	}
	_ = json.Unmarshal(n.Payload, &p)
	return cleanArtifactPaths(p.ArtifactPaths)
}

func isKeyFact(category string, evidenceIDs []string) bool {
	return category != "" && category != "general" || len(evidenceIDs) > 0
}

func isTaskGlobalKeyFact(category string, evidenceIDs []string, assets []int64, fromIntent int64) bool {
	if category == "scope_limit" {
		return true
	}
	return len(assets) == 0 && fromIntent == 0 && isKeyFact(category, evidenceIDs)
}

func isBareIPAsset(g EntryGraph, id int64) bool {
	if g.AssetTypes != nil {
		if typ := strings.TrimSpace(g.AssetTypes[id]); typ != "" {
			return typ == "ip"
		}
	}
	lbl := strings.TrimSpace(g.Assets[id])
	return lbl != "" && net.ParseIP(lbl) != nil
}

func assetLabelOf(labels map[int64]string, id int64) string {
	if labels != nil {
		if s := strings.TrimSpace(labels[id]); s != "" {
			return s
		}
	}
	return fmt.Sprintf("asset#%d", id)
}

func describeAsset(a *db.Asset) string {
	if a == nil {
		return ""
	}
	for _, s := range []string{a.URL, a.Domain, a.IP, a.ServiceName, a.AppName} {
		if strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	if a.Type != "" {
		return fmt.Sprintf("%s#%d", a.Type, a.ID)
	}
	return fmt.Sprintf("asset#%d", a.ID)
}

func uniqueIDs(ids []int64) []int64 {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[int64]bool, len(ids))
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id <= 0 || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func overlapsID(a, b []int64) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	set := make(map[int64]bool, len(b))
	for _, id := range b {
		set[id] = true
	}
	for _, id := range a {
		if set[id] {
			return true
		}
	}
	return false
}

func overlapsSet(ids []int64, set map[int64]bool) bool {
	if len(ids) == 0 || len(set) == 0 {
		return false
	}
	for _, id := range ids {
		if set[id] {
			return true
		}
	}
	return false
}

// entrySeedFactIDSet is the set of fact ids the entry seed already carries, used
// to drop them from the worker's situational overview so the same facts are not
// re-sent every turn in both the system prompt (seed) and the launch user message
// (overview). Non-selected facts stay retrievable via list_facts / node_detail.
// Only facts the seed actually renders count: facts dropped by the caps must stay
// visible in the overview's recent_facts.
func entrySeedFactIDSet(seed WorkerEntrySeed) map[int64]bool {
	keys, general, _, _ := selectedEntrySeedFacts(seed)
	if len(keys)+len(general) == 0 {
		return nil
	}
	m := make(map[int64]bool, len(keys)+len(general))
	for _, f := range append(keys, general...) {
		m[f.ID] = true
	}
	return m
}

// selectedEntrySeedFacts applies the render caps: up to entrySeedKeyFactCap key
// facts (intent-relevant and scope/cleanup constraints prioritized before
// unrelated-host key facts, oldest first within each tier), then general facts
// filling up to entrySeedFactCap (protecting direct parent facts alongside the
// newest relevant general facts).
func selectedEntrySeedFacts(seed WorkerEntrySeed) (keys, general []EntryFact, omittedKeys, omittedGeneral int) {
	for _, fact := range seed.ConfirmedFacts {
		if isKeyFact(fact.Category, fact.EvidenceIDs) {
			keys = append(keys, fact)
		} else {
			general = append(general, fact)
		}
	}
	keyTier := func(f EntryFact) int {
		if f.DirectParent || f.Relevant || f.Category == "scope_limit" || f.Category == "cleanup_status" {
			return 0
		}
		return 1
	}
	sort.Slice(keys, func(i, j int) bool {
		ti, tj := keyTier(keys[i]), keyTier(keys[j])
		if ti != tj {
			return ti < tj
		}
		return keys[i].ID < keys[j].ID
	})
	sort.Slice(general, func(i, j int) bool {
		if general[i].DirectParent != general[j].DirectParent {
			return !general[i].DirectParent
		}
		return general[i].ID < general[j].ID
	})
	keyCount, generalCount := len(keys), len(general)
	if len(keys) > entrySeedKeyFactCap {
		keys = keys[:entrySeedKeyFactCap]
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].ID < keys[j].ID })
	generalSlots := entrySeedFactCap - len(keys)
	if len(general) > generalSlots {
		general = general[len(general)-generalSlots:]
	}
	sort.Slice(general, func(i, j int) bool { return general[i].ID < general[j].ID })
	return keys, general, keyCount - len(keys), generalCount - len(general)
}

func inferIntentAssetIDs(intentPayload string, assets map[int64]string) []int64 {
	intentText := strings.ToLower(intentPayload)
	if intentText == "" || len(assets) == 0 {
		return nil
	}
	var matched []int64
	for id, label := range assets {
		if id <= 0 {
			continue
		}
		host := assetHostToken(label)
		if host == "" {
			continue
		}
		if containsHostToken(intentText, host) {
			matched = append(matched, id)
		}
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i] < matched[j] })
	return matched
}

func assetHostToken(label string) string {
	s := strings.TrimSpace(label)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			s = u.Hostname()
		}
	} else if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.ToLower(strings.Trim(strings.TrimSpace(s), "[]"))
	if len(s) < 4 {
		return ""
	}
	if !strings.Contains(s, ".") && net.ParseIP(s) == nil {
		return ""
	}
	return s
}

func containsHostToken(text, host string) bool {
	if text == "" || host == "" {
		return false
	}
	offset := 0
	for {
		idx := strings.Index(text[offset:], host)
		if idx < 0 {
			return false
		}
		start := offset + idx
		end := start + len(host)
		beforeOK := start == 0 || !isHostTokenChar(text[start-1])
		afterOK := end == len(text) || !isHostTokenChar(text[end])
		if beforeOK && afterOK {
			return true
		}
		offset = start + 1
	}
}

func isHostTokenChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '.' || b == '-' || b == '_'
}
