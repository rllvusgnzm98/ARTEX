package db

import (
	"testing"
)

func TestRecordFindingDeduplicatesSameCVEOrTitleOnSameAsset(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	task, err := d.CreateTask("finding dedup", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.DeleteTask(task.ID) }()

	assetID, err := d.Assets().UpsertIP(UpsertIPReq{TaskID: task.ID, IP: "192.168.111.79"})
	if err != nil {
		t.Fatal(err)
	}
	es := d.Exploration(task.ExplorationID)
	i1, err := es.AddNode(KindIntent, map[string]any{"summary": "exploit worker 1"}, 5, "open", "planner", []int64{assetID})
	if err != nil {
		t.Fatal(err)
	}
	i2, err := es.AddNode(KindIntent, map[string]any{"summary": "exploit worker 2"}, 5, "open", "planner", []int64{assetID})
	if err != nil {
		t.Fatal(err)
	}

	first, err := es.RecordFinding(t.Context(), RecordFindingInput{
		TaskID: task.ID, ExplorationID: task.ExplorationID, IntentID: i1,
		VulnClass: "RCE", Name: "PHP-CGI CVE-2024-4577 RCE", Severity: "critical",
		Summary: "whoami=system", Evidence: "p1", Worker: "w1", AssetIDs: []int64{assetID},
	})
	if err != nil {
		t.Fatalf("first RecordFinding: %v", err)
	}

	// Second intent reports the exact same CVE-2024-4577 on the same asset with a different title -> merges!
	dup, err := es.RecordFinding(t.Context(), RecordFindingInput{
		TaskID: task.ID, ExplorationID: task.ExplorationID, IntentID: i2,
		VulnClass: "PHP-CGI 远程代码执行", Name: "192.168.111.79 CVE-2024-4577", Severity: "critical",
		Summary: "same vuln duplicate", Evidence: "p2", Worker: "w2", AssetIDs: []int64{assetID},
	})
	if err != nil {
		t.Fatalf("dup RecordFinding: %v", err)
	}
	if dup.FindingID != first.FindingID || dup.NodeID != first.NodeID {
		t.Fatalf("expected CVE duplicate to return finding %d/node %d, got finding %d/node %d", first.FindingID, first.NodeID, dup.FindingID, dup.NodeID)
	}

	// Distinct vulnerability on the same asset -> creates a separate finding.
	other, err := es.RecordFinding(t.Context(), RecordFindingInput{
		TaskID: task.ID, ExplorationID: task.ExplorationID, IntentID: i2,
		VulnClass: "RCE", Name: "MS17-010 SMB RCE", Severity: "critical",
		Summary: "different vuln", Evidence: "p3", Worker: "w2", AssetIDs: []int64{assetID},
	})
	if err != nil {
		t.Fatalf("other RecordFinding: %v", err)
	}
	if other.FindingID == first.FindingID {
		t.Fatalf("distinct vulnerability must create separate finding, got same id %d", other.FindingID)
	}

	var count int
	if err := d.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1`, task.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("findings count = %d, want 2", count)
	}
}
