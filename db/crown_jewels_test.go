package db

import "testing"

// Crown Jewels (目标导向分析): marking an asset, goal→asset anchoring, and the
// per-exploration standing toward a target (reached? attack-path lineage? frontier
// distance?).
func TestCrownJewelStatus(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	as := d.Assets()

	aid, err := as.UpsertRootDomain(UpsertRootDomainReq{Domain: "crown-jewel.example"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM assets WHERE id=$1`, aid)

	if err := as.SetCrownJewel(aid, true, "payment processor"); err != nil {
		t.Fatal(err)
	}
	jewels, err := as.CrownJewels()
	if err != nil {
		t.Fatal(err)
	}
	var found *Asset
	for _, j := range jewels {
		if j.ID == aid {
			found = j
		}
	}
	if found == nil || !found.CrownJewel || found.CrownJewelNote != "payment processor" {
		t.Fatalf("crown jewel not listed with note: %+v", found)
	}

	expID, err := d.CreateExploration("test", "reach crown jewel")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	es := d.Exploration(expID)

	// goal anchored to the crown jewel asset (reuses exploration_anchors)
	goal, err := es.AddGoal(map[string]any{"text": "own payments"}, "human")
	if err != nil {
		t.Fatal(err)
	}
	if err := es.Anchor(goal, aid); err != nil {
		t.Fatal(err)
	}
	gids, err := es.AnchoredGoalIDs(aid)
	if err != nil || len(gids) != 1 || gids[0] != goal {
		t.Fatalf("AnchoredGoalIDs=%v err=%v", gids, err)
	}

	// Before any node touches the asset: unreached, no frontier distance.
	intent, err := es.AddIntent(map[string]any{"summary": "probe payments api"}, 8, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	st, err := es.CrownJewelStatusFor(aid)
	if err != nil {
		t.Fatal(err)
	}
	if st.ReachedByFinding {
		t.Fatalf("should not be reached yet: %+v", st)
	}

	// A finding yields from the intent and is anchored to the asset → reached, with
	// an attack path (intent→finding) and a frontier distance.
	find, err := es.AddNode("finding", map[string]any{"summary": "idor on payments", "severity": "high"}, 9, "confirmed", "worker", []int64{aid})
	if err != nil {
		t.Fatal(err)
	}
	if err := es.Link(intent, "yields", find); err != nil {
		t.Fatal(err)
	}
	st, err = es.CrownJewelStatusFor(aid)
	if err != nil {
		t.Fatal(err)
	}
	if !st.ReachedByFinding {
		t.Fatalf("finding should mark reached_by_finding: %+v", st)
	}
	if len(st.Path) == 0 || st.Path[len(st.Path)-1].ID != find {
		t.Fatalf("path should end at the reaching finding: %+v", st.Path)
	}
	if st.FrontierDistance == nil || *st.FrontierDistance < 0 {
		t.Fatalf("frontier distance should be computed: %+v", st)
	}

	// Unmark clears the flag + note.
	if err := as.SetCrownJewel(aid, false, ""); err != nil {
		t.Fatal(err)
	}
	jewels, _ = as.CrownJewels()
	for _, j := range jewels {
		if j.ID == aid {
			t.Fatalf("asset still listed as crown jewel after unmark")
		}
	}
}
