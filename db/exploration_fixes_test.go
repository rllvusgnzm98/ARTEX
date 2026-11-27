package db

import (
	"context"
	"testing"
)

func TestStopOpenIntents(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	expID, err := d.CreateExploration("stop open intents", "cleanup open intents on done")
	if err != nil {
		t.Fatalf("CreateExploration: %v", err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) })
	es := d.Exploration(expID)

	open1, err := es.AddIntent(map[string]any{"summary": "open 1"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	open2, err := es.AddIntent(map[string]any{"summary": "open 2"}, 3, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	runningID, err := es.AddIntent(map[string]any{"summary": "running"}, 7, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := es.ClaimIntent(runningID, "w1"); err != nil || !ok {
		t.Fatalf("ClaimIntent: ok=%v err=%v", ok, err)
	}
	doneID, err := es.AddIntent(map[string]any{"summary": "done"}, 6, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := es.SetIntentState(doneID, "done"); err != nil {
		t.Fatal(err)
	}

	n, err := es.StopOpenIntents(context.Background())
	if err != nil {
		t.Fatalf("StopOpenIntents: %v", err)
	}
	if n != 2 {
		t.Fatalf("StopOpenIntents updated %d rows, want 2", n)
	}
	for _, id := range []int64{open1, open2} {
		node, err := es.GetNode(id)
		if err != nil || node == nil {
			t.Fatalf("GetNode(%d): %v", id, err)
		}
		var hasCompletedAt bool
		var contentVer int
		if qerr := d.QueryRow(`SELECT completed_at IS NOT NULL, content_version FROM exploration_nodes WHERE id=$1`, id).Scan(&hasCompletedAt, &contentVer); qerr != nil {
			t.Fatalf("query node %d: %v", id, qerr)
		}
		if node.State != "stopped" || !hasCompletedAt || contentVer < 1 {
			t.Fatalf("open intent %d not properly stopped: state=%s completed_at=%v content_version=%d", id, node.State, hasCompletedAt, contentVer)
		}
	}
	if r, _ := es.GetNode(runningID); r == nil || r.State != "running" {
		t.Fatalf("running intent must stay running: %+v", r)
	}
	if dn, _ := es.GetNode(doneID); dn == nil || dn.State != "done" {
		t.Fatalf("done intent must stay done: %+v", dn)
	}
}

func TestMultiWordTraceSearchAndFallback(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	expID, err := d.CreateExploration("trace search", "multi-word search")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) })
	es := d.Exploration(expID)

	i1, err := es.AddIntent(map[string]any{"summary": "worker 1"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	i2, err := es.AddIntent(map[string]any{"summary": "worker 2"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := es.AppendActivity(Activity{
		NodeID: &i1, Worker: "w1", Kind: "tool_use", Tool: "Bash",
		Summary: "probed Apache gateway", Detail: "found Struts2 showcase endpoint on port 8080",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := es.AppendActivity(Activity{
		NodeID: &i2, Worker: "w2", Kind: "tool_use", Tool: "Bash",
		Summary: "probed Nginx only", Detail: "static asset 404",
	}); err != nil {
		t.Fatal(err)
	}

	// Multi-word AND across summary + detail regardless of word order.
	hits, err := es.ActivityTraceSearch(nil, "struts2 apache", 10)
	if err != nil {
		t.Fatalf("ActivityTraceSearch AND: %v", err)
	}
	if len(hits) != 1 || hits[0].Worker != "w1" {
		t.Fatalf("expected only w1 hit for AND query, got %+v", hits)
	}

	// OR fallback when AND produces 0 hits.
	orHits, err := es.ActivityTraceSearch(nil, "nginx missing_keyword", 10)
	if err != nil {
		t.Fatalf("ActivityTraceSearch OR fallback: %v", err)
	}
	if len(orHits) != 1 || orHits[0].Worker != "w2" {
		t.Fatalf("expected OR fallback to return w2, got %+v", orHits)
	}

	// ActivityTraceSearchExcluding excludes own nodeID.
	excl, err := es.ActivityTraceSearchExcluding(i1, "apache nginx", 10)
	if err != nil {
		t.Fatalf("ActivityTraceSearchExcluding: %v", err)
	}
	if len(excl) != 1 || excl[0].Worker != "w2" {
		t.Fatalf("expected excluding i1 to return only w2, got %+v", excl)
	}
}

func TestEntrySeedFactsExcludesDigestCovered(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	expID, err := d.CreateExploration("entry seed facts", "exclude active digest covered")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) })
	es := d.Exploration(expID)

	// Create 2 key facts (category=evidence) and 2 normal facts (category=general).
	keyCovered, err := es.AddNode(KindFact, map[string]any{"summary": "key covered", "category": "evidence"}, 5, "confirmed", "w1", nil)
	if err != nil {
		t.Fatal(err)
	}
	keyOpen, err := es.AddNode(KindFact, map[string]any{"summary": "key open", "category": "evidence"}, 5, "confirmed", "w1", nil)
	if err != nil {
		t.Fatal(err)
	}
	genCovered, err := es.AddNode(KindFact, map[string]any{"summary": "gen covered", "category": "general"}, 5, "confirmed", "w1", nil)
	if err != nil {
		t.Fatal(err)
	}
	genSuperseded, err := es.AddNode(KindFact, map[string]any{"summary": "gen superseded", "category": "general"}, 5, "confirmed", "w1", nil)
	if err != nil {
		t.Fatal(err)
	}

	activeDigest, err := es.AddNode(KindDigest, map[string]any{"summary": "cold digest"}, 0, "active", "compactor", nil)
	if err != nil {
		t.Fatal(err)
	}
	supersededDigest, err := es.AddNode(KindDigest, map[string]any{"summary": "old digest"}, 0, "superseded", "compactor", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := es.Link(activeDigest, RelCovers, keyCovered); err != nil {
		t.Fatal(err)
	}
	if err := es.Link(activeDigest, RelCovers, genCovered); err != nil {
		t.Fatal(err)
	}
	if err := es.Link(supersededDigest, RelCovers, genSuperseded); err != nil {
		t.Fatal(err)
	}

	keyFacts, err := es.EntrySeedFacts(true)
	if err != nil {
		t.Fatalf("EntrySeedFacts(true): %v", err)
	}
	if len(keyFacts) != 1 || keyFacts[0].ID != keyOpen {
		t.Fatalf("EntrySeedFacts(true) = %+v, want only [%d]", keyFacts, keyOpen)
	}

	genFacts, err := es.EntrySeedFacts(false)
	if err != nil {
		t.Fatalf("EntrySeedFacts(false): %v", err)
	}
	if len(genFacts) != 1 || genFacts[0].ID != genSuperseded {
		t.Fatalf("EntrySeedFacts(false) = %+v, want only [%d]", genFacts, genSuperseded)
	}
}
