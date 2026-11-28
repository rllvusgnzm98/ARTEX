package server

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// 成本态势注入的端到端回归：真实任务 + llm_usage 行 + 意图节点，验证
// costSituational 生成紧凑单行、lane 聚合正确、低产判定与降级路径（无数据不注入）。
func TestCostSituationalRendering(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())

	task, err := m.CreateTask("cost-situational 测试任务", "测试成本注入", nil, 0, 0)
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	t.Cleanup(func() {
		_, _ = m.pg.Exec(`DELETE FROM llm_usage WHERE task_id=$1`, task.ID)
		_, _ = m.DeleteTask(task.ID, DeleteTaskOptions{})
	})
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)

	// 无数据 → 不注入（降级路径：录制刚开/被关时 planner 不得报错或被阻断）。
	if got := s.costSituational(taskID); got != "" {
		t.Errorf("no-data case must yield empty injection, got %q", got)
	}

	// 造两个意图节点：#A 终态 done 零产出低成本（低产）、#B done 有产出。
	addIntent := func(summary string) int64 {
		id, err := task.Store.AddIntent(map[string]any{"summary": summary}, 5, nil, "")
		if err != nil {
			t.Fatalf("add intent: %v", err)
		}
		return id
	}
	lowID := addIntent("对账单资产摸排")
	highID := addIntent("主站漏洞验证")
	for _, id := range []int64{lowID, highID} {
		if err := task.Store.SetIntentState(id, "done"); err != nil {
			t.Fatalf("set intent state: %v", err)
		}
	}
	// highID 有产出事实 → 不是低产。
	fid, err := task.Store.AddFactCtx(context.Background(), map[string]any{"text": "evidence"}, "", nil, highID)
	if err != nil {
		t.Fatalf("add fact: %v", err)
	}
	if err := task.Store.Link(highID, db.RelYields, fid); err != nil {
		t.Fatalf("link yields: %v", err)
	}

	// 成本行：lowID 低成本（0.4K 级）、highID 高成本；planner lane 单独一行。
	ins := func(intentID int64, lane string, in, out int) {
		u := &db.LLMUsage{TaskID: task.ID, Worker: "worker", IntentID: intentID,
			WorkerInstance: lane, InputTokens: in, OutputTokens: out, Status: "ok"}
		if err := m.pg.InsertLLMUsage(u); err != nil {
			t.Fatalf("insert usage: %v", err)
		}
	}
	ins(lowID, "work#1", 300, 100)    // 0.4K，低成本零产出 → 低产
	ins(highID, "work#1", 9000, 1000) // 10K，有产出
	ins(0, "planner", 4000, 1000)     // planner lane 5K，intent_id NULL 不入意图聚合

	got := s.costSituational(taskID)
	if got == "" {
		t.Fatal("with usage data the injection must be non-empty")
	}
	for _, want := range []string{
		"【成本态势",
		"work#1", "planner",
		"已完成意图均值",
		"低产",
		fmt.Sprintf("#%d", lowID),
		"对账单资产摸排",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("injection missing %q:\n%s", want, got)
		}
	}
	// 高产意图不应被标进低产列表。
	lowSection := ""
	if i := strings.Index(got, "低产"); i >= 0 {
		lowSection = got[i:]
	}
	if strings.Contains(lowSection, fmt.Sprintf("#%d", highID)) {
		t.Errorf("productive intent #%d wrongly flagged as low-yield:\n%s", highID, got)
	}
	// planner lane 的 5K token 出现在 lane 聚合但不该进意图均值（均值=(0.4K+10K)/2=5.2K）。
	if !strings.Contains(got, "5.2K") {
		t.Errorf("mean of done intents (5.2K) missing:\n%s", got)
	}

	// 不存在的任务 → 空串（删库/竞态下不得 panic 或报错）。
	if got := s.costSituational(99999999); got != "" {
		t.Errorf("missing task must yield empty injection, got %q", got)
	}
}

// compactTokens 单位压缩：与态势行展示的紧凑格式绑定。
func TestCompactTokens(t *testing.T) {
	cases := map[int]string{
		0:        "0",
		999:      "999",
		1000:     "1.0K",
		1530:     "1.5K",
		999999:   "1000.0K",
		1000000:  "1.0M",
		41200000: "41.2M",
	}
	for in, want := range cases {
		if got := compactTokens(in); got != want {
			t.Errorf("compactTokens(%d)=%q want %q", in, got, want)
		}
	}
}
