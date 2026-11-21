package agent

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestGraphSnapshotMatchesDirectReads(t *testing.T) {
	_, assets, es, factID, assetID := setupConfirmedReconFact(t)
	tools := NewToolSet(es, "planner")
	tools.SetAssetStore(assets, assets.Companies())
	for i := 0; i < 3; i++ {
		if _, err := es.AddNode(db.KindFact, map[string]any{"summary": "extra fact", "confidence": "observed"}, 0, "confirmed", "worker", []int64{assetID}); err != nil {
			t.Fatalf("AddNode: %v", err)
		}
	}
	if _, err := es.AddNode(db.KindGoal, map[string]any{"text": "goal"}, 0, "open", "planner", nil); err != nil {
		t.Fatalf("AddNode goal: %v", err)
	}
	parent, _ := json.Marshal(factID)
	anchor, _ := json.Marshal(assetID)
	intentID, err := tools.addOneIntent(intentItem{Summary: "继续核验", ParentIDs: []json.RawMessage{parent}, AssetIDs: []json.RawMessage{anchor}})
	if err != nil {
		t.Fatalf("addOneIntent: %v", err)
	}

	snap := newGraphSnapshot(es)
	for _, tc := range []struct {
		kind  string
		limit int
	}{{db.KindFact, 1000}, {db.KindFact, 2}, {db.KindGoal, 100}, {db.KindIntent, 300}, {db.KindFinding, 0}} {
		want, err := es.ListByKind(tc.kind, tc.limit)
		if err != nil {
			t.Fatal(err)
		}
		got, err := snap.listByKind(tc.kind, tc.limit)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(want) {
			t.Fatalf("%s/%d: len %d want %d", tc.kind, tc.limit, len(got), len(want))
		}
		for i := range want {
			if got[i].ID != want[i].ID {
				t.Fatalf("%s/%d: order mismatch at %d: %d vs %d", tc.kind, tc.limit, i, got[i].ID, want[i].ID)
			}
		}
	}
	wantEdges, _ := es.Edges(5000)
	gotEdges, _ := snap.edgeList(5000)
	if len(wantEdges) == 0 || !sameEdges(gotEdges, wantEdges) {
		t.Fatalf("edges mismatch: got %v want %v", gotEdges, wantEdges)
	}

	ovWant, _ := json.Marshal(tools.graphOverviewData())
	ovGot, _ := json.Marshal(tools.graphOverviewDataFrom(snap))
	if string(ovGot) != string(ovWant) {
		t.Fatalf("overview mismatch:\n got %s\nwant %s", ovGot, ovWant)
	}

	intent, err := es.GetNode(intentID)
	if err != nil || intent == nil {
		t.Fatalf("Get intent: %v", err)
	}
	seedWant := LoadWorkerEntrySeed(es, assets, intent)
	seedGot := loadWorkerEntrySeedFrom(es, snap, assets, intent)
	if !reflect.DeepEqual(seedGot, seedWant) {
		t.Fatalf("entry seed mismatch:\n got %+v\nwant %+v", seedGot, seedWant)
	}
	if !seedHasReconFact(seedGot, factID) {
		t.Fatal("entry seed lost the confirmed recon fact")
	}
}

func sameEdges(a, b []db.Edge) bool {
	if len(a) != len(b) {
		return false
	}
	count := map[db.Edge]int{}
	for _, e := range a {
		count[e]++
	}
	for _, e := range b {
		count[e]--
	}
	for _, n := range count {
		if n != 0 {
			return false
		}
	}
	return true
}

func TestRenderTmplCachesParsedTemplate(t *testing.T) {
	const src = "hi {{.Name}}"
	for i := 0; i < 3; i++ {
		out, err := renderTmpl(src, struct{ Name string }{"a"})
		if err != nil || out != "hi a" {
			t.Fatalf("render: %q %v", out, err)
		}
	}
	first, _ := tmplCache.Load(src)
	if _, err := renderTmpl(src, struct{ Name string }{"b"}); err != nil {
		t.Fatal(err)
	}
	if again, _ := tmplCache.Load(src); again != first {
		t.Fatal("template was reparsed instead of reused")
	}
	if _, err := renderTmpl("{{.Missing}}", struct{ Name string }{"a"}); err == nil {
		t.Fatal("missingkey=error must still fail on unknown fields")
	}
	if _, err := renderTmpl("{{", nil); err == nil {
		t.Fatal("parse errors must surface")
	}
}
