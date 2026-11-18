package agent

import (
	"fmt"
	"sort"

	"github.com/Autumn-27/artex/db"
)

// OrderClaimSlots ranks open intents so worker slots are claimed by
// "confirmed reachable but not yet delivered" next hops first — the same
// notion BuildWorkerEntrySeed already uses at entry. When the graph cannot
// be read or no next hop is visible, the original order is kept (fail-soft).
// This function does not write intent, goal, or target state.
func OrderClaimSlots(intents []*db.Node, seedOf func(*db.Node) WorkerEntrySeed) []*db.Node {
	out := append([]*db.Node(nil), intents...)
	if len(out) <= 1 || seedOf == nil {
		return out
	}
	type item struct {
		n   *db.Node
		hop int
		pri int
		id  int64
		idx int
	}
	items := make([]item, len(out))
	anyHop := false
	for i, n := range out {
		it := item{n: n, idx: i}
		if n != nil {
			it.pri = n.Priority
			it.id = n.ID
		}
		seed := seedOf(n)
		it.hop = nextHopScore(seed)
		if it.hop > 0 {
			anyHop = true
		}
		items[i] = it
	}
	if !anyHop {
		return out
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].hop != items[j].hop {
			return items[i].hop > items[j].hop
		}
		if items[i].pri != items[j].pri {
			return items[i].pri > items[j].pri
		}
		return items[i].id < items[j].id
	})
	for i, it := range items {
		out[i] = it.n
	}
	return out
}

// OrderClaimSlotsFromGraph ranks intents using one in-memory graph snapshot,
// projecting each intent through BuildWorkerEntrySeed so next-hop scoring
// stays consistent with the entry seed.
func OrderClaimSlotsFromGraph(intents []*db.Node, g EntryGraph) []*db.Node {
	return OrderClaimSlots(intents, func(n *db.Node) WorkerEntrySeed {
		return seedFromGraph(g, n)
	})
}

// LoadSlotGraph reads the exploration graph once for claim ordering. It
// calls attachStoredGraphIncomplete so a stored compaction-failure signal
// fail-softs the same way worker entry does. It does not run compaction
// and does not rewrite the compactor-resilience hook.
func LoadSlotGraph(ts *db.ExplorationStore, as *db.AssetStore) EntryGraph {
	g := EntryGraph{Anchors: map[int64][]int64{}, Assets: map[int64]string{}}
	if ts == nil {
		g.PrefetchErr = fmt.Errorf("exploration store missing")
		return g
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
	anchors, err := ts.NodeAssets(nodeIDs)
	collect(err)
	if anchors != nil {
		g.Anchors = anchors
	}

	var assetIDs []int64
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
	return g
}

func seedFromGraph(base EntryGraph, intent *db.Node) WorkerEntrySeed {
	g := base
	g.Intent = intent
	if intent != nil {
		g.IntentAssetIDs = intentAssetIDs(intent)
	} else {
		g.IntentAssetIDs = nil
	}
	return BuildWorkerEntrySeed(g)
}

func nextHopScore(seed WorkerEntrySeed) int {
	if len(seed.NextHops) == 0 {
		return 0
	}
	n := 0
	for _, h := range seed.NextHops {
		if h.Continuation {
			n += 2
		} else {
			n += 1
		}
	}
	return n
}
