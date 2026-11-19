package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// setupConfirmedReconFact 写入一条已确认侦察事实及其资产锚,供 add_intent 下一跳夹具使用。
// 不连真实目标。
func setupConfirmedReconFact(t *testing.T) (*db.DB, *db.AssetStore, *db.ExplorationStore, int64, int64) {
	t.Helper()
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("nexthop preseed fixture", "continue from confirmed hosts", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	assets := d.Assets()
	assetID, err := assets.UpsertIP(db.UpsertIPReq{IP: "192.0.2.10", TaskID: task.ID})
	if err != nil {
		t.Fatalf("UpsertIP: %v", err)
	}
	es := d.Exploration(task.ExplorationID)
	factID, err := es.AddNode(db.KindFact, map[string]any{
		"summary":    "内网被动侦察：192.0.2.10 已确认可达",
		"detail":     "只读侦察看到 192.0.2.10，尚未对其继续核验",
		"confidence": "observed",
	}, 0, "confirmed", "worker", []int64{assetID})
	if err != nil {
		t.Fatalf("AddNode fact: %v", err)
	}
	return d, assets, es, factID, assetID
}

func seedHasReconFact(seed WorkerEntrySeed, factID int64) bool {
	for _, f := range seed.ConfirmedFacts {
		if f.ID == factID || strings.Contains(f.Summary, "内网被动侦察") || strings.Contains(f.Detail, "192.0.2.10") {
			return true
		}
	}
	return false
}

func TestAddIntentParentPathPreseedsConfirmedReconFacts(t *testing.T) {
	_, assets, es, factID, assetID := setupConfirmedReconFact(t)
	tools := NewToolSet(es, "planner")
	tools.SetAssetStore(assets, assets.Companies())

	parent, _ := json.Marshal(factID)
	anchor, _ := json.Marshal(assetID)
	nextID, err := tools.addOneIntent(intentItem{
		Summary:   "在已确认可达的主机上继续核验",
		ParentIDs: []json.RawMessage{parent},
		AssetIDs:  []json.RawMessage{anchor},
	})
	if err != nil {
		t.Fatalf("addOneIntent: %v", err)
	}
	next, err := es.GetNode(nextID)
	if err != nil || next == nil {
		t.Fatalf("GetNode next: %v", err)
	}

	seed := LoadWorkerEntrySeed(es, assets, next)
	if len(seed.Writes) != 0 {
		t.Fatalf("进场预塞必须只读, writes=%v", seed.Writes)
	}
	if !seedHasReconFact(seed, factID) {
		t.Fatalf("经 add_intent 挂 parent_ids 后,预塞应读到侦察 fact %d, 得到 %+v", factID, seed.ConfirmedFacts)
	}
	prompt := RenderWorkerEntrySeed(seed)
	if !strings.Contains(prompt, "内网被动侦察") && !strings.Contains(prompt, "192.0.2.10") {
		t.Fatalf("RenderWorkerEntrySeed 应包含已确认侦察事实:\n%s", prompt)
	}
}

func TestAddIntentAssetAnchorPathPreseedsConfirmedReconFacts(t *testing.T) {
	_, assets, es, factID, assetID := setupConfirmedReconFact(t)
	tools := NewToolSet(es, "planner")
	tools.SetAssetStore(assets, assets.Companies())

	// 不传 parent_ids(会兜底挂 origin),但带上与侦察事实重叠的资产锚。
	anchor, _ := json.Marshal(assetID)
	nextID, err := tools.addOneIntent(intentItem{
		Summary:  "针对已确认主机继续核验",
		AssetIDs: []json.RawMessage{anchor},
	})
	if err != nil {
		t.Fatalf("addOneIntent: %v", err)
	}
	next, err := es.GetNode(nextID)
	if err != nil || next == nil {
		t.Fatalf("GetNode next: %v", err)
	}
	if len(intentAssetIDs(next)) == 0 {
		t.Fatalf("本路径应带资产锚, payload=%s", next.Payload)
	}
	seed := LoadWorkerEntrySeed(es, assets, next)
	if !seedHasReconFact(seed, factID) {
		t.Fatalf("经 add_intent 带资产锚后,预塞应读到侦察 fact %d, 得到 %+v", factID, seed.ConfirmedFacts)
	}
}

func TestAddIntentWithoutEdgeOrAnchorDoesNotPreseedReconFacts(t *testing.T) {
	_, assets, es, factID, _ := setupConfirmedReconFact(t)

	// PR-E 负例契约:既无 derived_from 边、也无资产锚的新意图,预塞看不到侦察事实。
	// 不走 add_intent 兜底挂 origin,直接 AddIntent,以保持「无边无锚」的原合同。
	isolatedID, err := es.AddIntent(map[string]any{"summary": "unrelated new intent"}, 5, nil, "planner")
	if err != nil {
		t.Fatalf("AddIntent isolated: %v", err)
	}
	isolated, err := es.GetNode(isolatedID)
	if err != nil || isolated == nil {
		t.Fatalf("GetNode isolated: %v", err)
	}
	if len(isolated.Anchors) != 0 {
		t.Fatalf("夹具意图不应带资产锚, anchors=%v", isolated.Anchors)
	}
	seed := LoadWorkerEntrySeed(es, assets, isolated)
	if seedHasReconFact(seed, factID) {
		t.Fatalf("无 derived_from、无资产锚的新意图不应预塞侦察 fact %d: %+v", factID, seed.ConfirmedFacts)
	}
	if strings.Contains(RenderWorkerEntrySeed(seed), "内网被动侦察") {
		t.Fatalf("RenderWorkerEntrySeed 不应包含侦察摘要:\n%s", RenderWorkerEntrySeed(seed))
	}
}
