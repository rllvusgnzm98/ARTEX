package agent

import (
	"errors"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// openIntentC is an unrelated new-target intent on a third host. It is not a
// continuation of the confirmed-reachable neighborhood in multiStageGraph.
func openIntentC() *db.Node {
	return node(103, db.KindIntent, "open", map[string]any{
		"summary":   "在一个尚未有已确认事实的主机上开新方向",
		"asset_ids": []int64{33},
	})
}

func TestOrderClaimSlotsPrefersConfirmedReachableUndelivered(t *testing.T) {
	g, neighborhood := multiStageGraph()
	if len(neighborhood) < 2 {
		t.Fatal("acceptance fixture must be multi-host")
	}
	intentB := g.Intent
	if intentB == nil || intentB.ID != 102 {
		t.Fatalf("fixture intent B missing: %+v", intentB)
	}
	// Lower planner priority on the next-hop intent, higher on the new target:
	// next-hop still wins, because slots are ordered by confirmed-reachable-undelivered.
	intentB.Priority = 1
	intentC := openIntentC()
	intentC.Priority = 9

	ordered := OrderClaimSlotsFromGraph([]*db.Node{intentC, intentB}, g)
	if len(ordered) != 2 || ordered[0] == nil || ordered[0].ID != intentB.ID {
		t.Fatalf("next-hop intent B should be claimed first, got %+v", idsOf(ordered))
	}
	if ordered[1] == nil || ordered[1].ID != intentC.ID {
		t.Fatalf("unrelated new target should wait, got %+v", idsOf(ordered))
	}

	seedB := seedFromGraph(g, intentB)
	if len(seedB.ConfirmedFacts) == 0 || len(seedB.NextHops) == 0 {
		t.Fatalf("intent B should see prior confirmed facts and next hops: %+v", seedB)
	}
	seedC := seedFromGraph(g, intentC)
	if nextHopScore(seedB) <= nextHopScore(seedC) {
		t.Fatalf("B next-hop score=%d should exceed C score=%d", nextHopScore(seedB), nextHopScore(seedC))
	}
}

func TestOrderClaimSlotsSingleHostIsContrastOnly(t *testing.T) {
	// A single-host range may exist as contrast, but acceptance is multi-stage.
	singleIntent := node(2, db.KindIntent, "open", map[string]any{
		"summary":   "only one host",
		"asset_ids": []int64{11},
	})
	single := EntryGraph{
		Intent:         singleIntent,
		IntentAssetIDs: []int64{11},
		Facts: []*db.Node{node(3, db.KindFact, "confirmed", map[string]any{
			"summary":    "edge.example.test reachable",
			"confidence": "observed",
		})},
		Edges:   []db.Edge{{From: 3, Rel: db.RelDerivedFrom, To: 2}},
		Anchors: map[int64][]int64{3: {11}, 2: {11}},
		Assets:  map[int64]string{11: "edge.example.test"},
	}
	multi, neighborhood := multiStageGraph()
	if len(neighborhood) < 2 {
		t.Fatal("acceptance fixture must be multi-host")
	}
	if len(BuildWorkerEntrySeed(single).NextHops) == 0 {
		t.Fatal("single-host contrast should still pre-seed its one hop")
	}
	follow := multi.Intent
	if nextHopScore(seedFromGraph(multi, follow)) == 0 {
		t.Fatal("follow-on intent must score as a next hop on the acceptance fixture")
	}
}

func TestOrderClaimSlotsFailSoftKeepsOriginalOrder(t *testing.T) {
	g, _ := multiStageGraph()
	g.PrefetchErr = errors.New("list facts failed")
	g.CompressErr = errors.New("compressor unavailable")
	g.Facts = nil
	g.Edges = nil
	g.Anchors = map[int64][]int64{}
	first := openIntentC()
	first.Priority = 1
	second := g.Intent
	second.Priority = 0
	in := []*db.Node{first, second}
	ordered := OrderClaimSlotsFromGraph(in, g)
	if len(ordered) != 2 || ordered[0] != first || ordered[1] != second {
		t.Fatalf("incomplete graph must fail-soft and keep original order, got %+v", idsOf(ordered))
	}
	copied := OrderClaimSlots(in, nil)
	if copied[0] != first || copied[1] != second {
		t.Fatalf("nil seed func should keep original order, got %+v", idsOf(copied))
	}
}

func TestYieldWhenNoMarginalProgress(t *testing.T) {
	// Slot yield is the same stop-loss decision: once a run has no marginal
	// progress, the intent settles exhausted and the slot can be reclaimed.
	loss := EvaluateStopLoss(tightPolicy(), ProgressSignals{
		FactsKnown: true, AssetsKnown: true, CommandsKnown: true,
		IdleProbes: 2, Elapsed: time.Minute,
	})
	if !loss.Fired() {
		t.Fatalf("no marginal progress should fire stop-loss: %+v", loss)
	}
	if got := IntentStateAfterRun("", nil, loss); got != "exhausted" {
		t.Fatalf("yielded slot should settle exhausted (not done, not a goal failure), got %s", got)
	}
	if loss.TargetFailureWrites != 0 {
		t.Fatal("yielding a slot must not write target failure")
	}
}

func idsOf(nodes []*db.Node) []int64 {
	out := make([]int64, 0, len(nodes))
	for _, n := range nodes {
		if n == nil {
			out = append(out, 0)
			continue
		}
		out = append(out, n.ID)
	}
	return out
}
