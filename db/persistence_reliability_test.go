package db

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// 本文件覆盖阶段四的三件事，都必须实连 PostgreSQL 才算验证过（外键、事务回滚、
// JSONB 默认值都是「编译通过也可能运行时失败」的东西）：
//   1. 锚点引用不存在的 asset 时，写入显式失败且整个事务回滚（不留下半个节点）；
//   2. 落库失败在健康登记表里可见，而不是只进日志；
//   3. 运行溯源只在首次真跑时写一次，旧任务如实报「未知」。

func reliabilityTestDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// newReliabilityTask 建一个任务（连带 exploration），并登记清理。清理在 d.Close
// 之前跑：Cleanup 是后进先出，而 Close 是在 reliabilityTestDB 里先登记的。
func newReliabilityTask(t *testing.T, d *DB, name string) *Task {
	t.Helper()
	task, err := d.CreateTaskWithOptions(name, "阶段四持久化可靠性", TaskCreateOptions{})
	if err != nil {
		t.Fatalf("建任务失败: %v", err)
	}
	t.Cleanup(func() {
		d.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID)
		d.Exec(`DELETE FROM explorations WHERE id=$1`, task.ExplorationID)
	})
	return task
}

// newReliabilityAsset 建一个真实 asset，用于「锚点合法」的对照组。
func newReliabilityAsset(t *testing.T, d *DB, taskID int64) int64 {
	t.Helper()
	domain := fmt.Sprintf("anchor-%d-%d.example.test", taskID, time.Now().UnixNano())
	var id int64
	if err := d.QueryRow(`
INSERT INTO assets(type, domain, root_domain, task_ids)
VALUES ('root_domain',$1,$1,ARRAY[$2]::bigint[])
RETURNING id`, domain, taskID).Scan(&id); err != nil {
		t.Fatalf("建 asset 失败: %v", err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM assets WHERE id=$1`, id) })
	return id
}

func countNodes(t *testing.T, d *DB, expID int64) int {
	t.Helper()
	var n int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1`, expID).Scan(&n); err != nil {
		t.Fatalf("数节点失败: %v", err)
	}
	return n
}

// TestAddNodeRejectsDanglingAnchor 确认锚点引用不存在的 asset 时：
//   - 返回可识别的 ErrDanglingAnchor（而不是裸的 23503 驱动错误）；
//   - 错误里带上具体缺失的 asset id；
//   - 节点一行都没留下（事务整体回滚，不会出现「有节点没锚点」的半成品）。
func TestAddNodeRejectsDanglingAnchor(t *testing.T) {
	d := reliabilityTestDB(t)
	task := newReliabilityTask(t, d, "锚点悬空-"+t.Name())
	store := d.Exploration(task.ExplorationID)
	ctx := context.Background()

	var missing int64
	if err := d.QueryRow(`SELECT COALESCE(MAX(id),0)+1000 FROM assets`).Scan(&missing); err != nil {
		t.Fatalf("取不存在的 asset id 失败: %v", err)
	}

	before := countNodes(t, d, task.ExplorationID)
	_, err := store.AddNodeCtx(ctx, KindFact, map[string]any{"summary": "悬空锚点"}, 5, "confirmed", "test", []int64{missing})
	if err == nil {
		t.Fatal("锚点引用不存在的 asset,AddNodeCtx 却成功了")
	}
	if !errors.Is(err, ErrDanglingAnchor) {
		t.Fatalf("期望 ErrDanglingAnchor,实际: %v", err)
	}
	var dangling *DanglingAnchorError
	if !errors.As(err, &dangling) {
		t.Fatalf("期望 *DanglingAnchorError,实际: %v", err)
	}
	if len(dangling.Missing) != 1 || dangling.Missing[0] != missing {
		t.Fatalf("错误里缺失的 asset id 不对: %v (期望 [%d])", dangling.Missing, missing)
	}
	if after := countNodes(t, d, task.ExplorationID); after != before {
		t.Fatalf("事务没回滚: 节点数 %d → %d", before, after)
	}

	// 健康登记表里要能看到这次悬空锚点,而不是只在日志里。
	snap := d.Health().Snapshot(task.ExplorationID)
	if snap.DanglingAnchors == 0 {
		t.Fatal("健康快照没记录悬空锚点")
	}
	if snap.Healthy() {
		t.Fatal("有悬空锚点却报告健康")
	}
}

// TestAddNodeAcceptsLiveAnchor 是对照组:合法锚点照常写入,校验没有误伤。
func TestAddNodeAcceptsLiveAnchor(t *testing.T) {
	d := reliabilityTestDB(t)
	task := newReliabilityTask(t, d, "锚点正常-"+t.Name())
	asset := newReliabilityAsset(t, d, task.ID)
	store := d.Exploration(task.ExplorationID)
	ctx := context.Background()

	id, err := store.AddNodeCtx(ctx, KindFact, map[string]any{"summary": "正常锚点"}, 5, "confirmed", "test", []int64{asset})
	if err != nil {
		t.Fatalf("合法锚点写入失败: %v", err)
	}
	var anchors int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_anchors WHERE node_id=$1 AND asset_id=$2`, id, asset).Scan(&anchors); err != nil {
		t.Fatalf("查锚点失败: %v", err)
	}
	if anchors != 1 {
		t.Fatalf("锚点没写进去: count=%d", anchors)
	}
	if snap := d.Health().Snapshot(task.ExplorationID); !snap.Healthy() {
		t.Fatalf("正常写入却报告不健康: %+v", snap)
	}
}

// TestAnchorCtxRejectsDanglingAsset 覆盖单独补锚点的路径(AnchorCtx)。
func TestAnchorCtxRejectsDanglingAsset(t *testing.T) {
	d := reliabilityTestDB(t)
	task := newReliabilityTask(t, d, "补锚点悬空-"+t.Name())
	store := d.Exploration(task.ExplorationID)
	ctx := context.Background()

	nodeID, err := store.AddNodeCtx(ctx, KindFact, map[string]any{"summary": "待补锚点"}, 5, "confirmed", "test", nil)
	if err != nil {
		t.Fatalf("建节点失败: %v", err)
	}
	var missing int64
	if err := d.QueryRow(`SELECT COALESCE(MAX(id),0)+1000 FROM assets`).Scan(&missing); err != nil {
		t.Fatalf("取不存在的 asset id 失败: %v", err)
	}
	if err := store.AnchorCtx(ctx, nodeID, missing); !errors.Is(err, ErrDanglingAnchor) {
		t.Fatalf("AnchorCtx 期望 ErrDanglingAnchor,实际: %v", err)
	}
	var anchors int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_anchors WHERE node_id=$1`, nodeID).Scan(&anchors); err != nil {
		t.Fatalf("查锚点失败: %v", err)
	}
	if anchors != 0 {
		t.Fatalf("失败的锚点却留下了行: count=%d", anchors)
	}
}

// TestRunProvenanceStampedOnceAndLegacyUnknown 确认运行溯源:
//   - 首次盖章记下真实版本与脱敏配置;
//   - 再次盖章不改写(第一次真跑的 build 才是产生数据的 build);
//   - 没盖过章的旧任务如实报 Recorded=false,不拿当前版本顶替。
func TestRunProvenanceStampedOnceAndLegacyUnknown(t *testing.T) {
	d := reliabilityTestDB(t)
	task := newReliabilityTask(t, d, "运行溯源-"+t.Name())
	legacy := newReliabilityTask(t, d, "旧任务无溯源-"+t.Name())

	if prov, err := d.TaskProvenance(legacy.ID); err != nil {
		t.Fatalf("读旧任务溯源失败: %v", err)
	} else if prov.Recorded || prov.BuildVersion != "" {
		t.Fatalf("旧任务不该有溯源证据: %+v", prov)
	}

	want := map[string]any{"stop_loss": map[string]any{"idle_probe_limit": 6}, "config": map[string]any{"gate_mode": "warn"}}
	if err := d.StampRunProvenance(task.ID, "v-test-1", want); err != nil {
		t.Fatalf("盖章失败: %v", err)
	}
	prov, err := d.TaskProvenance(task.ID)
	if err != nil {
		t.Fatalf("读溯源失败: %v", err)
	}
	if !prov.Recorded || prov.BuildVersion != "v-test-1" {
		t.Fatalf("溯源版本不对: %+v", prov)
	}
	if prov.Runtime["config"] == nil || prov.Runtime["stop_loss"] == nil {
		t.Fatalf("有效配置快照没落库: %+v", prov.Runtime)
	}

	// 升级后重启不得改写既有证据。
	if err := d.StampRunProvenance(task.ID, "v-test-2", map[string]any{"build_version": "v-test-2"}); err != nil {
		t.Fatalf("二次盖章失败: %v", err)
	}
	again, err := d.TaskProvenance(task.ID)
	if err != nil {
		t.Fatalf("再读溯源失败: %v", err)
	}
	if again.BuildVersion != "v-test-1" {
		t.Fatalf("既有溯源被改写成了 %q", again.BuildVersion)
	}
}

// TestPersistenceHealthTracksLoss 不连库:健康登记表本身的语义。活动丢失、写入失败
// 必须累计可见,并能按 exploration 清理。
func TestPersistenceHealthTracksLoss(t *testing.T) {
	h := NewPersistenceHealth()
	if !h.Snapshot(7).Healthy() {
		t.Fatal("没有失败记录时应为健康")
	}
	h.RecordDroppedActivity(7, "fk_violation(23503,父exploration不存在)")
	h.RecordDroppedActivity(7, "disk_full(53100,磁盘写满)")
	h.RecordWriteFailure(7, "run_provenance: boom")
	h.RecordDanglingAnchors(7, []int64{42, 42, 7}, "dangling")

	snap := h.Snapshot(7)
	if snap.DroppedActivity != 2 {
		t.Fatalf("丢弃计数不对: %d", snap.DroppedActivity)
	}
	if snap.WriteFailures != 1 {
		t.Fatalf("写入失败计数不对: %d", snap.WriteFailures)
	}
	if snap.DanglingAnchors != 3 {
		t.Fatalf("悬空锚点计数不对: %d", snap.DanglingAnchors)
	}
	if len(snap.MissingAssets) != 2 {
		t.Fatalf("缺失 asset 去重后应为 2 个: %v", snap.MissingAssets)
	}
	if snap.Healthy() {
		t.Fatal("有失败记录却报告健康")
	}
	if snap.LastReason != "dangling" || snap.LastAt.IsZero() {
		t.Fatalf("最后一次失败原因/时间没记录: %+v", snap)
	}
	if got := h.Unhealthy(); len(got) != 1 {
		t.Fatalf("Unhealthy 应只含 1 个 exploration: %v", got)
	}
	h.Forget(7)
	if !h.Snapshot(7).Healthy() {
		t.Fatal("Forget 之后应回到健康")
	}
	// nil 登记表必须安全(没有 health 的写入路径照常工作)。
	var nilHealth *PersistenceHealth
	nilHealth.RecordDroppedActivity(1, "x")
	if !nilHealth.Snapshot(1).Healthy() {
		t.Fatal("nil 登记表应为健康")
	}
}
