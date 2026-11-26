package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestRecordFactIntentLookupDistinguishesDeadlineFromInvalidInput(t *testing.T) {
	d, es := retentionStore(t)
	intent, err := es.AddIntent(map[string]any{"summary": "record facts"}, 0, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	ts := NewToolSet(es, "worker")
	item := factItem{Summary: "checkpoint"}
	if _, err := ts.recordOneFactCtx(t.Context(), item, intent+1); err == nil || ts.Writes() != (WriteCounts{}) {
		t.Fatalf("missing intent: error=%v writes=%#v", err, ts.Writes())
	}
	lock, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if _, err := lock.Exec("LOCK TABLE exploration_nodes IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	if _, err := ts.recordOneFactCtx(ctx, item, intent); !errors.Is(err, context.DeadlineExceeded) || ts.Writes() != (WriteCounts{Failures: 1}) {
		t.Fatalf("blocked intent lookup: error=%v writes=%#v", err, ts.Writes())
	}
}

func TestRecordFactRollsBackWhenIntentLinkMissesDeadline(t *testing.T) {
	d, es := retentionStore(t)
	intent, err := es.AddIntent(map[string]any{"summary": "record facts"}, 0, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	ts := NewToolSet(es, "worker")
	before, err := es.CountByKind(db.KindFact)
	if err != nil {
		t.Fatal(err)
	}
	locker, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Rollback()
	if _, err := locker.Exec("LOCK TABLE exploration_edges IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	item := factItem{Summary: "checkpoint"}
	_, err = ts.recordOneFactCtx(ctx, item, intent)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "link fact to intent") {
		t.Fatalf("expected intent link deadline, got %v", err)
	}
	if err := locker.Rollback(); err != nil {
		t.Fatal(err)
	}
	if count, err := es.CountByKind(db.KindFact); err != nil || count != before || ts.Writes() != (WriteCounts{Failures: 1}) {
		t.Fatalf("orphan fact or incorrect counters: count=%d before=%d writes=%+v err=%v", count, before, ts.Writes(), err)
	}
	id, err := ts.recordOneFactCtx(t.Context(), item, intent)
	if err != nil {
		t.Fatal(err)
	}
	if ids, err := es.FactsYielded(intent); err != nil || !reflect.DeepEqual(ids, []int64{id}) {
		t.Fatalf("planner lookup: ids=%v err=%v, want [%d]", ids, err, id)
	}
}

func TestRecordFactStructuredPriority(t *testing.T) {
	_, es := retentionStore(t)
	tool := NewToolSet(es, "worker").recordFact()
	for _, category := range []string{"", "negative_result", "scope_limit", "cleanup_status", "evidence"} {
		t.Run("category="+category, func(t *testing.T) {
			input := map[string]any{"summary": "structured observation", "category": category, "evidence_ids": []string{"traffic:73", "artifact:cleanup.json"}}
			raw, _ := json.Marshal(input)
			result, err := tool.Call(t.Context(), raw, nil)
			if err != nil || result.IsError {
				t.Fatalf("record_fact failed: %s %v", result.Flatten(), err)
			}
			var id int64
			if _, err := fmt.Sscanf(result.Flatten(), "fact recorded: %d", &id); err != nil {
				t.Fatal(err)
			}
			n, err := es.GetNode(id)
			if err != nil {
				t.Fatal(err)
			}
			var got factItem
			if err := json.Unmarshal(n.Payload, &got); err != nil {
				t.Fatal(err)
			}
			if n.Kind != db.KindFact || got.Category != category || !reflect.DeepEqual(got.EvidenceIDs, input["evidence_ids"]) {
				t.Fatalf("structured payload lost or converted to finding: %s", n.Payload)
			}
		})
	}
	result, err := tool.Call(t.Context(), json.RawMessage(`{"summary":"plain observation"}`), nil)
	if err != nil || result.IsError {
		t.Fatalf("omitted optional fields: %s %v", result.Flatten(), err)
	}
	var id int64
	if _, err := fmt.Sscanf(result.Flatten(), "fact recorded: %d", &id); err != nil {
		t.Fatal(err)
	}
	n, err := es.GetNode(id)
	if err != nil {
		t.Fatal(err)
	}
	var plain map[string]any
	if err := json.Unmarshal(n.Payload, &plain); err != nil {
		t.Fatal(err)
	}
	if _, exists := plain["category"]; exists {
		t.Error("omitted category must remain general without changing legacy payloads")
	}
	if _, exists := plain["evidence_ids"]; exists {
		t.Error("omitted evidence_ids should not be written")
	}
	for _, input := range []string{
		`{"summary":"invalid","category":"finding"}`,
		`{"summary":"invalid","category":"general"}`,
		`{"summary":"invalid","evidence_ids":[3]}`,
		`{"summary":"invalid","evidence_ids":"not-a-list"}`,
		`{`,
	} {
		before, err := es.CountByKind(db.KindFact)
		if err != nil {
			t.Fatal(err)
		}
		result, err := tool.Call(t.Context(), json.RawMessage(input), nil)
		if err != nil || !result.IsError {
			t.Errorf("invalid input accepted: %s => %s, %v", input, result.Flatten(), err)
		}
		after, err := es.CountByKind(db.KindFact)
		if err != nil || before != after {
			t.Fatalf("invalid input wrote a fact: before=%d after=%d err=%v", before, after, err)
		}
	}
}

func TestRecordFactBatchPrioritySchema(t *testing.T) {
	_, es := retentionStore(t)
	tool := NewToolSet(es, "worker").recordFact()
	props := tool.InputSchema()["properties"].(map[string]any)
	itemProps := props["facts"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
	for _, p := range []map[string]any{props, itemProps} {
		category := p["category"].(map[string]any)
		if !reflect.DeepEqual(category["enum"], []string{"negative_result", "scope_limit", "cleanup_status", "evidence"}) {
			t.Errorf("missing category enum: %v", category)
		}
		ids := p["evidence_ids"].(map[string]any)
		if ids["type"] != "array" || ids["items"].(map[string]any)["type"] != "string" {
			t.Errorf("invalid evidence_ids schema: %v", ids)
		}
	}
	result, err := tool.Call(t.Context(), json.RawMessage(`{"facts":[{"summary":"one","category":"scope_limit","evidence_ids":["scope:1"]},{"summary":"bad","category":"finding"},{"summary":"plain","evidence_ids":[]}]}`), nil)
	if err != nil || result.IsError {
		t.Fatalf("batch failed: %s %v", result.Flatten(), err)
	}
	var got struct {
		IDs    []int64           `json:"ids"`
		Errors map[string]string `json:"errors"`
	}
	if err := json.Unmarshal([]byte(result.Flatten()), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.IDs) != 3 || got.IDs[0] == 0 || got.IDs[1] != 0 || got.IDs[2] == 0 || got.Errors["1"] == "" {
		t.Fatalf("invalid batch result: %+v", got)
	}
	n, err := es.GetNode(got.IDs[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(n.Payload), `"scope:1"`) || !strings.Contains(string(n.Payload), `"scope_limit"`) {
		t.Fatalf("batch fields lost: %s", n.Payload)
	}
}

func TestReportFindingRequiresAndFallsBackName(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("finding name test", "verify finding name fallback", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	es := d.Exploration(task.ExplorationID)
	ts := NewToolSet(es, "worker")
	ts.SetTaskID(task.ID)
	tool := ts.addFinding()

	req, _ := tool.InputSchema()["required"].([]string)
	hasName := false
	for _, r := range req {
		if r == "name" {
			hasName = true
		}
	}
	if !hasName {
		t.Fatalf("report_finding required=%v, want 'name' included", req)
	}

	// Omitting name derives a concise title from summary instead of storing empty name.
	res1, err := tool.Call(t.Context(), json.RawMessage(`{"vulnclass":"rce","severity":"critical","summary":"HugeGraph Gremlin 沙箱逃逸导致任意文件读取。详细过程见 evidence。"}`), nil)
	if err != nil || res1.IsError {
		t.Fatalf("report_finding without name failed: %s %v", res1.Flatten(), err)
	}
	var got1 db.RecordedFinding
	if _, body, ok := strings.Cut(res1.Flatten(), "\n"); !ok || json.Unmarshal([]byte(body), &got1) != nil || got1.FindingID <= 0 {
		t.Fatalf("unexpected report_finding response: %s", res1.Flatten())
	}
	var name1 string
	if err := d.QueryRow(`SELECT name FROM findings WHERE id=$1`, got1.FindingID).Scan(&name1); err != nil {
		t.Fatal(err)
	}
	if name1 != "HugeGraph Gremlin 沙箱逃逸导致任意文件读取" {
		t.Fatalf("derived finding name=%q, want concise first clause", name1)
	}

	// Explicit name is preserved verbatim.
	res2, err := tool.Call(t.Context(), json.RawMessage(`{"vulnclass":"rce","name":"Explicit Finding Title","severity":"high","summary":"long summary"}`), nil)
	if err != nil || res2.IsError {
		t.Fatalf("report_finding with explicit name failed: %s %v", res2.Flatten(), err)
	}
	var got2 db.RecordedFinding
	if _, body, ok := strings.Cut(res2.Flatten(), "\n"); !ok || json.Unmarshal([]byte(body), &got2) != nil || got2.FindingID <= 0 {
		t.Fatalf("unexpected report_finding response: %s", res2.Flatten())
	}
	var name2 string
	if err := d.QueryRow(`SELECT name FROM findings WHERE id=$1`, got2.FindingID).Scan(&name2); err != nil {
		t.Fatal(err)
	}
	if name2 != "Explicit Finding Title" {
		t.Fatalf("explicit finding name=%q, want 'Explicit Finding Title'", name2)
	}
}

func TestRecordFactInheritsIntentAssetAnchorsWhenOmitted(t *testing.T) {
	d, es := retentionStore(t)
	a1, err := d.Assets().UpsertSubdomain(db.UpsertSubdomainReq{Domain: "inherit1.acme.test"})
	if err != nil {
		t.Fatal(err)
	}
	a2, err := d.Assets().UpsertSubdomain(db.UpsertSubdomainReq{Domain: "explicit2.acme.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM assets WHERE id IN ($1, $2)`, a1, a2)

	intentID, err := es.AddIntent(map[string]any{"summary": "audit inherit1.acme.test"}, 5, []int64{a1}, "planner")
	if err != nil {
		t.Fatal(err)
	}

	ts := NewToolSet(es, "worker")
	// 1. Omitting asset_ids inherits intentID's exploration_anchors ([a1]).
	fInherited, err := ts.recordOneFactCtx(t.Context(), factItem{
		Summary:    "inherit1.acme.test 返回 500 堆栈",
		Confidence: "observed",
		Category:   "negative_result",
	}, intentID)
	if err != nil {
		t.Fatalf("recordOneFactCtx inherited failed: %v", err)
	}
	anchors, err := es.NodeAssets([]int64{fInherited})
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors[fInherited]) != 1 || anchors[fInherited][0] != a1 {
		t.Fatalf("inherited anchors=%v, want [%d]", anchors[fInherited], a1)
	}

	// 2. Explicit asset_ids override intent anchor inheritance.
	fExplicit, err := ts.recordOneFactCtx(t.Context(), factItem{
		Summary:    "explicit2.acme.test 关联测试",
		Confidence: "observed",
		AssetIDs:   []json.RawMessage{json.RawMessage(fmt.Sprintf("%d", a2))},
	}, intentID)
	if err != nil {
		t.Fatalf("recordOneFactCtx explicit failed: %v", err)
	}
	anchors2, err := es.NodeAssets([]int64{fExplicit})
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors2[fExplicit]) != 1 || anchors2[fExplicit][0] != a2 {
		t.Fatalf("explicit anchors=%v, want [%d]", anchors2[fExplicit], a2)
	}
}

func TestDanglingAssetAnchorDoesNotPoisonEvidenceFailureCount(t *testing.T) {
	d, es := retentionStore(t)
	var taskID int64
	if err := d.QueryRow(`SELECT id FROM tasks WHERE exploration_id=$1`, es.ID()).Scan(&taskID); err != nil {
		t.Fatal(err)
	}
	intentID, err := es.AddIntent(map[string]any{"summary": "verify dangling anchor error accounting"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}

	ts := NewToolSet(es, "worker")
	ts.SetTaskID(taskID)
	ts.SetAssetStore(d.Assets(), d.Companies())

	factIn, _ := json.Marshal(map[string]any{
		"summary":   "dangling anchor test fact",
		"intent_id": intentID,
		"asset_ids": []int64{999999999},
	})
	factRes, err := ts.recordFact().Call(t.Context(), factIn, nil)
	if err != nil || !factRes.IsError {
		t.Fatalf("expected record_fact to reject dangling asset anchor: res=%v err=%v", factRes.Flatten(), err)
	}

	findIn, _ := json.Marshal(map[string]any{
		"vulnclass": "RCE",
		"name":      "dangling anchor finding",
		"severity":  "high",
		"summary":   "finding with nonexistent asset anchor",
		"intent_id": intentID,
		"asset_ids": []int64{999999999},
		"evidence":  "uid=0(root)",
	})
	findRes, err := ts.addFinding().Call(t.Context(), findIn, nil)
	if err != nil || !findRes.IsError {
		t.Fatalf("expected report_finding to reject dangling asset anchor: res=%v err=%v", findRes.Flatten(), err)
	}

	if ts.Writes().Failures != 0 {
		t.Fatalf("dangling anchor client validation error must not increment Failures: got %+v", ts.Writes())
	}
}

func TestRecordFactArtifactPathsReachNextIntentSeed(t *testing.T) {
	_, es := retentionStore(t)
	ts := NewToolSet(es, "worker")
	intentA, err := es.AddIntent(map[string]any{"summary": "拿边界机 root"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	factID, err := ts.recordOneFactCtx(t.Context(), factItem{
		Summary:       "边界机 root SSH 私钥已写入共享目录",
		Confidence:    "observed",
		ArtifactPaths: []string{"/data/tasks/253/shared/id_rsa", "/data/tasks/253/shared/id_rsa", "  "},
	}, intentA)
	if err != nil {
		t.Fatal(err)
	}
	node, err := es.GetNode(factID)
	if err != nil || node == nil {
		t.Fatal(err)
	}
	var payload struct {
		Paths []string `json:"artifact_paths"`
	}
	if err := json.Unmarshal(node.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Paths) != 1 || payload.Paths[0] != "/data/tasks/253/shared/id_rsa" {
		t.Fatalf("artifact_paths = %#v", payload.Paths)
	}
	nextID, err := ts.addOneIntentCtx(t.Context(), intentItem{
		Summary:   "从 192.168.52.20 容器逃逸到宿主机",
		ParentIDs: []json.RawMessage{json.RawMessage(fmt.Sprintf("%d", factID))},
	})
	if err != nil {
		t.Fatal(err)
	}
	next, err := es.GetNode(nextID)
	if err != nil {
		t.Fatal(err)
	}
	out := RenderWorkerEntrySeed(LoadWorkerEntrySeed(es, nil, next))
	if !strings.Contains(out, "/data/tasks/253/shared/id_rsa") {
		t.Fatalf("downstream entry seed missing shared artifact:\n%s", out)
	}
}

func TestPlannerOverviewExposesTaskAssetIndex(t *testing.T) {
	d, es := retentionStore(t)
	var taskID int64
	if err := d.QueryRow(`SELECT id FROM tasks WHERE exploration_id=$1`, es.ID()).Scan(&taskID); err != nil {
		t.Fatal(err)
	}
	assetID, err := d.Assets().UpsertIP(db.UpsertIPReq{IP: "203.0.113.20", TaskID: taskID})
	if err != nil {
		t.Fatal(err)
	}
	ts := NewToolSet(es, "planner")
	ts.SetTaskID(taskID)
	ts.SetAssetStore(d.Assets(), d.Companies())
	ov := ts.graphOverviewData()
	list, _ := ov["task_assets"].([]map[string]any)
	found := false
	for _, item := range list {
		id, _ := item["id"].(int64)
		if id != assetID {
			continue
		}
		found = true
		if item["type"] != "ip" || item["host"] != "203.0.113.20" {
			t.Fatalf("asset index item = %+v", item)
		}
	}
	if !found {
		t.Fatalf("asset %d missing from task_assets: %+v", assetID, list)
	}
	rendered := renderWorkerGraphOverview(ov, nil)
	if strings.Contains(rendered, "task_assets") || strings.Contains(rendered, "203.0.113.20") {
		t.Fatalf("worker overview leaked planner asset index:\n%s", rendered)
	}
}
