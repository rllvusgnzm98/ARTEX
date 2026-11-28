package db

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// 成本聚合查询的回归测试：lane/意图维度分组必须与 llm_usage 的写入语义
// （intent_id 由 session_id 解析/attribution 写入）一致，否则 planner 的
// 成本态势会聚合出错误分组。
func TestCostByLaneAndIntent(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	taskID := "costq-" + uuid.NewString()
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM llm_usage WHERE task_id=$1`, taskID) })

	seed := []LLMUsage{
		{TaskID: taskID, Worker: "worker", IntentID: 101, WorkerInstance: "work#1", InputTokens: 1000, OutputTokens: 500, CacheRead: 200, CacheWrite: 100, Status: "ok"},
		{TaskID: taskID, Worker: "worker", IntentID: 102, WorkerInstance: "work#1", InputTokens: 2000, OutputTokens: 0, Status: "ok"},
		{TaskID: taskID, Worker: "worker", IntentID: 101, WorkerInstance: "work#2", InputTokens: 4000, OutputTokens: 300, CacheWrite: 50, Status: "error"},
		{TaskID: taskID, Worker: "planner", WorkerInstance: "planner", InputTokens: 800, OutputTokens: 100, Status: "ok"},
		// 无 lane 归因的行应归并到 '(unknown)'，不应丢失或拆碎。
		{TaskID: taskID, Worker: "worker", InputTokens: 50, OutputTokens: 5, Status: "ok"},
	}
	for i := range seed {
		if err := d.InsertLLMUsage(&seed[i]); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	// 让调用时间有序：意图 101 最后一次调用应晚于 102。
	if _, err := d.Exec(`UPDATE llm_usage SET ts = now() - interval '10 minute' WHERE task_id=$1 AND intent_id=102`, taskID); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	lanes, err := d.CostByLane(taskID)
	if err != nil {
		t.Fatalf("CostByLane: %v", err)
	}
	byLane := map[string]LaneCost{}
	for _, l := range lanes {
		byLane[l.Lane] = l
	}
	// work#1: 1000+500+200+100 + 2000 = 3800 tokens, 2 calls
	if l := byLane["work#1"]; l.Calls != 2 || l.TotalTokens() != 3800 {
		t.Errorf("work#1 = %+v, want calls=2 tokens=3800", l)
	}
	// work#2: 4000+300+50 = 4350
	if l := byLane["work#2"]; l.Calls != 1 || l.TotalTokens() != 4350 {
		t.Errorf("work#2 = %+v, want calls=1 tokens=4350", l)
	}
	// planner lane 回落：worker_instance='planner' 时 lane 键为 planner
	if l := byLane["planner"]; l.Calls != 1 || l.TotalTokens() != 900 {
		t.Errorf("planner = %+v, want calls=1 tokens=900", l)
	}
	// 无归因行：worker_instance 空时回落 worker 角色
	if l := byLane["worker"]; l.Calls != 1 || l.TotalTokens() != 55 {
		t.Errorf("worker fallback lane = %+v, want calls=1 tokens=55", l)
	}
	// 排序：最贵的 lane 在前（work#2 4350 > work#1 3800）
	if lanes[0].Lane != "work#2" {
		t.Errorf("lanes[0]=%s, want work#2 (most expensive first)", lanes[0].Lane)
	}

	intents, err := d.CostByIntent(taskID)
	if err != nil {
		t.Fatalf("CostByIntent: %v", err)
	}
	byIntent := map[int64]IntentCost{}
	for _, ic := range intents {
		byIntent[ic.IntentID] = ic
	}
	// 意图 101 跨两个 lane 的调用聚合：1000+500+200+100 + 4000+300+50 = 6150
	if ic := byIntent[101]; ic.Calls != 2 || ic.TotalTokens() != 6150 {
		t.Errorf("intent 101 = %+v, want calls=2 tokens=6150", ic)
	}
	if ic := byIntent[102]; ic.Calls != 1 || ic.TotalTokens() != 2000 {
		t.Errorf("intent 102 = %+v, want calls=1 tokens=2000", ic)
	}
	// 按最近调用倒序：101 的最后一次调用晚于 102 → 101 在前
	if len(intents) != 2 || intents[0].IntentID != 101 {
		t.Fatalf("intent order = %+v, want [101 102]", intents)
	}
	if !intents[0].LastCallAt.After(intents[1].LastCallAt.Add(-time.Second)) {
		t.Errorf("last_call_at not ordered: %v vs %v", intents[0].LastCallAt, intents[1].LastCallAt)
	}
	// intent_id 为 NULL 的行（planner/无归因）不进意图聚合
	for _, ic := range intents {
		if ic.IntentID != 101 && ic.IntentID != 102 {
			t.Errorf("unexpected intent %d in aggregation", ic.IntentID)
		}
	}
}

// 其他任务的行不得串进来（task_id 过滤是硬边界）。
func TestCostQueriesIsolatedByTask(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	a := "costiso-a-" + uuid.NewString()
	b := "costiso-b-" + uuid.NewString()
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM llm_usage WHERE task_id IN ($1,$2)`, a, b)
	})
	if err := d.InsertLLMUsage(&LLMUsage{TaskID: a, WorkerInstance: "work#1", IntentID: 1, InputTokens: 100, Status: "ok"}); err != nil {
		t.Fatal(err)
	}
	if err := d.InsertLLMUsage(&LLMUsage{TaskID: b, WorkerInstance: "work#9", IntentID: 1, InputTokens: 900, Status: "ok"}); err != nil {
		t.Fatal(err)
	}
	lanes, err := d.CostByLane(a)
	if err != nil {
		t.Fatal(err)
	}
	if len(lanes) != 1 || lanes[0].Lane != "work#1" || lanes[0].TotalTokens() != 100 {
		t.Errorf("task a lanes = %+v, want only work#1/100", lanes)
	}
	intents, err := d.CostByIntent(a)
	if err != nil {
		t.Fatal(err)
	}
	if len(intents) != 1 || intents[0].TotalTokens() != 100 {
		t.Errorf("task a intents = %+v, want single 100-token intent", intents)
	}
}

func TestPruneLLMRecords(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	if err := d.EnsureLLMRecordsTable(); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	tag := "prune-" + uuid.NewString()
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM llm_records WHERE task_id=$1`, tag)
	})
	for i := 0; i < 4; i++ {
		if err := d.InsertLLMRecord(&LLMRecord{Model: "m", SessionID: tag, TaskID: tag, Status: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	// Backdate the oldest of our 4 rows by 30 days to exercise age pruning.
	if _, err := d.Exec(`UPDATE llm_records SET ts = now() - interval '30 days'
		WHERE id = (SELECT MIN(id) FROM llm_records WHERE task_id=$1)`, tag); err != nil {
		t.Fatal(err)
	}
	prunedAge, err := d.PruneLLMRecords(t.Context(), 0, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("PruneLLMRecords age: %v", err)
	}
	if prunedAge < 1 {
		t.Fatalf("expected at least 1 expired row pruned, got %d", prunedAge)
	}
	var afterAge int
	if err := d.QueryRow(`SELECT COUNT(*) FROM llm_records WHERE task_id=$1`, tag).Scan(&afterAge); err != nil {
		t.Fatal(err)
	}
	if afterAge != 3 {
		t.Fatalf("expected 3 rows remaining after age prune, got %d", afterAge)
	}

	// Now prune by maxRows keeping only the 1 newest row globally (which is our newest row).
	if _, err := d.PruneLLMRecords(t.Context(), 1, 0); err != nil {
		t.Fatalf("PruneLLMRecords maxRows: %v", err)
	}
	var afterCap int
	if err := d.QueryRow(`SELECT COUNT(*) FROM llm_records WHERE task_id=$1`, tag).Scan(&afterCap); err != nil {
		t.Fatal(err)
	}
	if afterCap != 1 {
		t.Fatalf("expected 1 newest row remaining after maxRows prune, got %d", afterCap)
	}
}
