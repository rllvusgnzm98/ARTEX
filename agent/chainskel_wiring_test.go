package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent/chainskel"
	"github.com/Autumn-27/artex/db"
)

// 本文件的测试锁住 chainskel 与 agent 的接线:chain_tags 落进意图 payload、
// 非法标签在写库前被拒、worker 领到意图时的首条消息带上 L3 骨架与 L4 指引、
// planner/worker system 固定尾带 L2 meta 铁律。

func TestAddIntentPersistsChainTags(t *testing.T) {
	_, assets, es, _, _ := setupConfirmedReconFact(t)
	tools := NewToolSet(es, "planner")
	tools.SetAssetStore(assets, assets.Companies())

	id, err := tools.addOneIntent(intentItem{
		Summary:   "对目标接口做 sql 注入测试",
		ChainTags: []string{" Web ", "web", "PIVOT"},
	})
	if err != nil {
		t.Fatalf("addOneIntent: %v", err)
	}
	n, err := es.GetNode(id)
	if err != nil || n == nil {
		t.Fatalf("GetNode: %v", err)
	}
	var p struct {
		ChainTags []string `json:"chain_tags"`
	}
	if err := json.Unmarshal(n.Payload, &p); err != nil {
		t.Fatalf("payload 解析: %v", err)
	}
	want := []string{"web", "pivot"}
	if len(p.ChainTags) != len(want) {
		t.Fatalf("chain_tags 应规整去重后落库, got %v want %v", p.ChainTags, want)
	}
	for i := range want {
		if p.ChainTags[i] != want[i] {
			t.Fatalf("chain_tags 应规整去重后落库, got %v want %v", p.ChainTags, want)
		}
	}
}

func TestAddIntentRejectsInvalidChainTags(t *testing.T) {
	_, assets, es, _, _ := setupConfirmedReconFact(t)
	tools := NewToolSet(es, "planner")
	tools.SetAssetStore(assets, assets.Companies())

	if _, err := tools.addOneIntent(intentItem{
		Summary:   "云上横向",
		ChainTags: []string{"cloud"},
	}); err == nil || !strings.Contains(err.Error(), "chain_tags 含非法取值") {
		t.Fatalf("非法取值应在写库前被拒, got %v", err)
	}
	if _, err := tools.addOneIntent(intentItem{
		Summary:   "三面开打",
		ChainTags: []string{"web", "ad", "priv"},
	}); err == nil || !strings.Contains(err.Error(), "至多") {
		t.Fatalf("超量标签应在写库前被拒, got %v", err)
	}
	// 被拒的意图不得落库。
	intents, err := es.ListByKind(db.KindIntent, 50)
	if err != nil {
		t.Fatalf("ListByKind: %v", err)
	}
	for _, n := range intents {
		var p struct {
			Summary string `json:"summary"`
		}
		_ = json.Unmarshal(n.Payload, &p)
		if p.Summary == "云上横向" || p.Summary == "三面开打" {
			t.Fatalf("非法 chain_tags 的意图不应落库: %+v", p)
		}
	}
}

func TestAddIntentNoChainTagsOmitsPayloadKey(t *testing.T) {
	_, assets, es, _, _ := setupConfirmedReconFact(t)
	tools := NewToolSet(es, "planner")
	tools.SetAssetStore(assets, assets.Companies())

	id, err := tools.addOneIntent(intentItem{Summary: "常规巡检"})
	if err != nil {
		t.Fatalf("addOneIntent: %v", err)
	}
	n, err := es.GetNode(id)
	if err != nil || n == nil {
		t.Fatalf("GetNode: %v", err)
	}
	if strings.Contains(string(n.Payload), "chain_tags") {
		t.Fatalf("无标签时不应写空 chain_tags 键(保持 payload 干净): %s", string(n.Payload))
	}
}

func TestRenderIntentTaskInjectsSkeleton(t *testing.T) {
	_, assets, es, _, _ := setupConfirmedReconFact(t)
	tools := NewToolSet(es, "planner")
	tools.SetAssetStore(assets, assets.Companies())

	id, err := tools.addOneIntent(intentItem{
		Summary:   "对该站做注入测试",
		ChainTags: []string{"web"},
	})
	if err != nil {
		t.Fatalf("addOneIntent: %v", err)
	}
	n, err := es.GetNode(id)
	if err != nil || n == nil {
		t.Fatalf("GetNode: %v", err)
	}
	msg := renderIntentTask(n)
	if !strings.Contains(msg, `<chains-skeleton source="chains-skeleton" category="web">`) {
		t.Fatalf("worker 首条消息应注入 web 骨架:\n%s", msg)
	}
	if !strings.Contains(msg, "skills/chains-web/refs/") {
		t.Fatalf("worker 首条消息应带 L4 原文指引:\n%s", msg)
	}
	// 意图正文仍在最前面(worker 先读任务再读骨架):骨架块必须排在意图正文之后。
	intentIdx := strings.Index(msg, "【你领到的意图")
	skelIdx := strings.Index(msg, "<chains-skeleton")
	if intentIdx < 0 || skelIdx < 0 || skelIdx < intentIdx {
		t.Fatalf("骨架块应在意图正文之后, intentIdx=%d skelIdx=%d", intentIdx, skelIdx)
	}
}

func TestRenderIntentTaskKeywordFallback(t *testing.T) {
	// 无 chain_tags 时靠 summary 关键词回退,同样注入。
	n := &db.Node{ID: 7, Payload: []byte(`{"summary":"内网隧道选型与横向"}`)}
	if msg := renderIntentTask(n); !strings.Contains(msg, `category="pivot"`) {
		t.Fatalf("无标签应关键词回退注入 pivot:\n%s", msg)
	}
	// 匹配不中静默不注入。
	n2 := &db.Node{ID: 8, Payload: []byte(`{"summary":"随便看看"}`)}
	if msg := renderIntentTask(n2); strings.Contains(msg, "chains-skeleton") {
		t.Fatalf("匹配不中不应注入骨架:\n%s", msg)
	}
}

func TestSystemPromptsCarryMetaRules(t *testing.T) {
	plan := plannerSystem("目标", t.TempDir(), t.TempDir())
	if !strings.Contains(plan, "meta 铁律") || !strings.Contains(plan, "梯度为零") {
		t.Fatal("planner system 固定尾应带 L2 meta 铁律")
	}
	work := workerSystem("", "", t.TempDir(), t.TempDir(), false, DefaultFootprint())
	if !strings.Contains(work, "meta 铁律") || !strings.Contains(work, "回显阴性从不等于漏洞阴性") {
		t.Fatal("worker system 固定尾应带 L2 meta 铁律")
	}
	// 两份文本不互相串味:planner 版覆盖派活纪律,worker 版只留观测真伪+卡住自检。
	if !strings.Contains(plan, chainskel.PlannerMetaRules) {
		t.Fatal("planner 应原样使用 PlannerMetaRules")
	}
	if !strings.Contains(work, chainskel.WorkerMetaRules) {
		t.Fatal("worker 应原样使用 WorkerMetaRules")
	}
	if strings.Contains(work, "派意图按利用成熟度") {
		t.Fatal("worker system 不应含 planner 专属派活纪律")
	}
}
