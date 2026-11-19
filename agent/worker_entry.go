package agent

import (
	"encoding/json"
	"fmt"
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
	// Writes is always empty when produced by LoadWorkerEntrySeed / BuildWorkerEntrySeed:
	// prefetch is read-only. Tests assert this so a prefetch failure cannot be
	// recorded as a target/goal failure.
	Writes []string
}

// EntryFact is one confirmed fact relevant to the claimed intent.
type EntryFact struct {
	ID         int64
	Summary    string
	Detail     string
	Confidence string
	AssetIDs   []int64
	Assets     []string
	FromIntent int64
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
		"prove_goal", "goal_met", "register_session", "session_recon":
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
		node       *db.Node
		summary    string
		detail     string
		confidence string
		assets     []int64
		from       int64
	}
	var confirmed []factView
	byID := map[int64]factView{}
	for _, n := range g.Facts {
		if n == nil || n.State == db.StateOrigin {
			continue
		}
		summary, detail, conf := factFields(n)
		if !isConfirmedFact(n.State, conf) {
			continue
		}
		fv := factView{
			node:       n,
			summary:    summary,
			detail:     detail,
			confidence: conf,
			assets:     uniqueIDs(anchorOf(n.ID)),
			from:       producedBy[n.ID],
		}
		confirmed = append(confirmed, fv)
		byID[n.ID] = fv
	}

	relevant := map[int64]bool{}
	seedAnchors := map[int64]bool{}
	mark := func(id int64) {
		fv, ok := byID[id]
		if !ok || relevant[id] {
			return
		}
		relevant[id] = true
		for _, a := range fv.assets {
			seedAnchors[a] = true
		}
	}
	for id := range parentFacts {
		mark(id)
	}
	for id := range siblingFacts {
		mark(id)
	}
	for _, fv := range confirmed {
		if overlapsID(fv.assets, intentAssets) {
			mark(fv.node.ID)
		}
	}
	// One expansion: confirmed facts that share an anchor with the seed set
	// (prior-stage observations on a host this hop is continuing from).
	for _, fv := range confirmed {
		if overlapsSet(fv.assets, seedAnchors) {
			mark(fv.node.ID)
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
			ID:         fv.node.ID,
			Summary:    fv.summary,
			Detail:     fv.detail,
			Confidence: fv.confidence,
			AssetIDs:   fv.assets,
			Assets:     labels,
			FromIntent: fv.from,
		})
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].ID < facts[j].ID })
	seed.ConfirmedFacts = facts

	// Neighborhood of confirmed-reachable assets, minus those already delivered.
	factIDsFor := map[int64][]int64{}
	for _, f := range facts {
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
	if seed.GraphIncomplete {
		b.WriteString("若出现「" + GraphIncompleteMarker + "」，先用只读工具把能读到的补上，再行动。")
	}

	if len(seed.ConfirmedFacts) == 0 {
		b.WriteString("\n\n【进场预塞】没有与本意图相关的已确认事实。第一次工具仍须先读图（list_facts）。")
		return b.String()
	}

	b.WriteString("\n\n【进场预塞：与本意图相关的已确认事实】\n")
	for _, f := range seed.ConfirmedFacts {
		conf := f.Confidence
		if conf == "" {
			conf = "confirmed"
		}
		fmt.Fprintf(&b, "- fact #%d (%s)：%s", f.ID, conf, strings.TrimSpace(f.Summary))
		if len(f.Assets) > 0 {
			fmt.Fprintf(&b, "（资产：%s）", strings.Join(f.Assets, "、"))
		}
		if f.FromIntent > 0 {
			fmt.Fprintf(&b, "［来自意图 #%d］", f.FromIntent)
		}
		b.WriteByte('\n')
		if d := strings.TrimSpace(f.Detail); d != "" {
			fmt.Fprintf(&b, "  细节：%s\n", d)
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
	g := EntryGraph{Intent: intent, Anchors: map[int64][]int64{}, Assets: map[int64]string{}}
	if intent != nil {
		g.IntentAssetIDs = intentAssetIDs(intent)
	}
	if ts == nil {
		g.PrefetchErr = fmt.Errorf("exploration store missing")
		return BuildWorkerEntrySeed(g)
	}

	if _, _, err := loadColdGraph(ts); err != nil {
		g.CompressErr = err
	}
	attachStoredGraphIncomplete(&g, ts)

	var prefetchErr error
	collect := func(err error) {
		if err != nil && prefetchErr == nil {
			prefetchErr = err
		}
	}

	facts, err := ts.ListByKind(db.KindFact, 1000)
	collect(err)
	g.Facts = facts
	findings, err := ts.ListByKind(db.KindFinding, 1000)
	collect(err)
	g.Findings = findings
	goals, err := ts.ListByKind(db.KindGoal, 200)
	collect(err)
	g.Goals = goals
	edges, err := ts.Edges(5000)
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
