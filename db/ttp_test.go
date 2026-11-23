package db

import "testing"

// TTP review pipeline: entries are pending until approved; ApprovedTTPLines (the
// runtime chainskel overlay) only surfaces approved ones, in chainskel line format.
func TestTTPReviewPipeline(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	id, err := d.AddTTPEntry(TTPEntry{Source: "retro", Category: "web",
		Scene: "疑似注入参数", Criteria: "看可复现真假分叉", Pivot: "无分叉换时间盲"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM ttp_entries WHERE id=$1`, id)

	wid, err := d.AddTTPEntry(TTPEntry{Source: "writeup", Category: "web", Confidence: 0.4,
		OriginRef: "https://example.test/writeup", Scene: "x", Criteria: "y", Pivot: "z"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM ttp_entries WHERE id=$1`, wid)

	// Pending entries must NOT appear in the approved overlay.
	lines, err := d.ApprovedTTPLines("web")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		if l == TTPLine(TTPEntry{Scene: "疑似注入参数", Criteria: "看可复现真假分叉", Pivot: "无分叉换时间盲"}) {
			t.Fatalf("pending entry leaked into approved overlay")
		}
	}

	pend, err := d.ListTTPEntries("pending")
	if err != nil || len(pend) < 2 {
		t.Fatalf("expected >=2 pending, got %d err=%v", len(pend), err)
	}

	// Approve the retro entry → it joins the overlay; reject the writeup → it never does.
	if _, changed, err := d.SetTTPStatus(id, "approved", "human"); err != nil || !changed {
		t.Fatalf("approve failed: changed=%v err=%v", changed, err)
	}
	if _, changed, err := d.SetTTPStatus(wid, "rejected", "human"); err != nil || !changed {
		t.Fatalf("reject failed: changed=%v err=%v", changed, err)
	}
	// A second review on an already-settled entry is a no-op (single-winner guard).
	if _, changed, _ := d.SetTTPStatus(id, "rejected", "human"); changed {
		t.Fatalf("second review on a settled entry must report changed=false")
	}
	lines, err = d.ApprovedTTPLines("web")
	if err != nil {
		t.Fatal(err)
	}
	want := TTPLine(TTPEntry{Scene: "疑似注入参数", Criteria: "看可复现真假分叉", Pivot: "无分叉换时间盲"})
	found := false
	for _, l := range lines {
		if l == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("approved entry missing from overlay: %v", lines)
	}
	got, _ := d.GetTTPEntry(wid)
	if got == nil || got.Status != "rejected" || got.ReviewedAt == nil {
		t.Fatalf("writeup should be rejected+stamped: %+v", got)
	}
}
