package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
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

// TestLegacyRanTaskStaysUnknownAfterUpgrade 覆盖「升级前就跑过的任务」：schema 的回填
// 把它标成 legacy-unknown，之后再怎么启动都报「构建未知」，绝不被当前 build 顶替——
// 否则旧证据会被归因到升级后的新版本。还没真正跑过的任务不受影响，首次跑时照常盖章。
func TestLegacyRanTaskStaysUnknownAfterUpgrade(t *testing.T) {
	d := reliabilityTestDB(t)
	ran := newReliabilityTask(t, d, "升级前跑过-"+t.Name())
	fresh := newReliabilityTask(t, d, "还没跑过-"+t.Name())

	// 模拟旧库：跑过（status 已离开 created），但没有任何溯源列。
	if _, err := d.Exec(`UPDATE tasks SET status='running', build_version='' WHERE id=$1`, ran.ID); err != nil {
		t.Fatalf("构造旧任务失败: %v", err)
	}
	if _, err := d.Exec(`UPDATE tasks SET build_version='' WHERE id=$1`, fresh.ID); err != nil {
		t.Fatalf("构造新任务失败: %v", err)
	}

	// 与 schema.sql 同一条回填语句。
	if _, err := d.Exec(`UPDATE tasks SET build_version = 'legacy-unknown'
 WHERE build_version = '' AND (first_run_at IS NOT NULL OR status <> 'created')`); err != nil {
		t.Fatalf("回填失败: %v", err)
	}

	prov, err := d.TaskProvenance(ran.ID)
	if err != nil {
		t.Fatalf("读旧任务溯源失败: %v", err)
	}
	if prov.Recorded {
		t.Fatalf("升级前跑过的任务不该被当成有证据: %+v", prov)
	}
	if prov.BuildVersion != LegacyUnknownBuild {
		t.Fatalf("旧任务该标为 %q，实际 %q", LegacyUnknownBuild, prov.BuildVersion)
	}

	// 升级后它又被调度起来：不得把新 build 写成它的「第一次运行」。
	if err := d.StampRunProvenance(ran.ID, "v-after-upgrade", map[string]any{"build_version": "v-after-upgrade"}); err != nil {
		t.Fatalf("盖章失败: %v", err)
	}
	if again, err := d.TaskProvenance(ran.ID); err != nil {
		t.Fatalf("再读旧任务溯源失败: %v", err)
	} else if again.BuildVersion != LegacyUnknownBuild || again.Recorded {
		t.Fatalf("旧任务被回填成了 %+v", again)
	}

	// 真没跑过的任务不受回填影响，首次真跑照常留证。
	if err := d.StampRunProvenance(fresh.ID, "v-first", map[string]any{"build_version": "v-first"}); err != nil {
		t.Fatalf("新任务盖章失败: %v", err)
	}
	if got, err := d.TaskProvenance(fresh.ID); err != nil {
		t.Fatalf("读新任务溯源失败: %v", err)
	} else if !got.Recorded || got.BuildVersion != "v-first" {
		t.Fatalf("新任务首次盖章没生效: %+v", got)
	}
}

// TestAnchorWriteErrMapsFKViolation 不连库：去掉校验时的 FOR SHARE 后，校验与写入之间
// 的并发清理由外键兜底，这里确认它被按**约束名**翻译成对应的一致性错误并登记健康表。
// exploration_anchors 两列都有外键，只看 SQLSTATE 会把「owner 节点没了」误报成
// 「asset 没了」，所以约束名拿不到时宁可原样返回，也不猜。
func TestAnchorWriteErrMapsFKViolation(t *testing.T) {
	h := NewPersistenceHealth()
	assetFK := &pgconn.PgError{Code: "23503", ConstraintName: anchorAssetFK}
	err := anchorWriteErr(assetFK, h, 11, 99, []int64{5, 5, 3})
	if !errors.Is(err, ErrDanglingAnchor) {
		t.Fatalf("asset 外键冲突该翻译成悬空锚点错误，实际 %v", err)
	}
	var dangling *DanglingAnchorError
	if !errors.As(err, &dangling) {
		t.Fatalf("该带上缺失 id: %v", err)
	}
	if len(dangling.Missing) != 2 || dangling.Missing[0] != 3 || dangling.Missing[1] != 5 {
		t.Fatalf("缺失 id 该去重排序，实际 %v", dangling.Missing)
	}
	if snap := h.Snapshot(11); snap.Healthy() || snap.DanglingAnchors == 0 {
		t.Fatalf("悬空锚点该在健康表里可见: %+v", snap)
	}

	ownerFK := &pgconn.PgError{Code: "23503", ConstraintName: anchorOwnerFK}
	ownerErr := anchorWriteErr(ownerFK, h, 12, 77, []int64{5})
	if errors.Is(ownerErr, ErrDanglingAnchor) {
		t.Fatalf("owner 节点缺失不该误报成 asset 缺失: %v", ownerErr)
	}
	var owner *MissingAnchorOwnerError
	if !errors.As(ownerErr, &owner) || owner.NodeID != 77 {
		t.Fatalf("该报成挂靠节点不存在并带上节点 id，实际 %v", ownerErr)
	}
	if snap := h.Snapshot(12); snap.Healthy() {
		t.Fatalf("owner 缺失也该在健康表里可见: %+v", snap)
	}

	// 约束名拿不到时不猜（不同 PG 版本/手工建库都可能没有），原样返回。
	bare := &pgconn.PgError{Code: "23503"}
	if got := anchorWriteErr(bare, h, 13, 1, []int64{3}); got != error(bare) {
		t.Fatalf("约束名未知时该原样返回，实际 %v", got)
	}

	other := errors.New("连接断了")
	if got := anchorWriteErr(other, h, 11, 1, []int64{3}); got != other {
		t.Fatalf("非外键错误该原样返回，实际 %v", got)
	}
	if anchorWriteErr(nil, h, 11, 1, []int64{3}) != nil {
		t.Fatal("nil 该返回 nil")
	}
}

// TestAnchorOwnerNodeFKIsDistinct 覆盖评审指出的张冠李戴：exploration_anchors 两列都有
// 外键，asset 还在、挂靠的节点没了时也是 23503。按约束名区分之后，这种情形必须报成
// MissingAnchorOwnerError 而不是「asset 不存在」。
func TestAnchorOwnerNodeFKIsDistinct(t *testing.T) {
	d := reliabilityTestDB(t)
	task := newReliabilityTask(t, d, "锚点owner缺失-"+t.Name())
	asset := newReliabilityAsset(t, d, task.ID)
	store := d.Exploration(task.ExplorationID)

	// 建一个节点再删掉：asset 仍然健在，owner 节点已不存在。
	nodeID, err := store.AddFactCtx(context.Background(), map[string]any{"text": "owner"}, "test", nil, 0)
	if err != nil {
		t.Fatalf("建节点失败: %v", err)
	}
	if _, err := d.Exec(`DELETE FROM exploration_nodes WHERE id=$1`, nodeID); err != nil {
		t.Fatalf("删节点失败: %v", err)
	}

	err = store.AnchorCtx(context.Background(), nodeID, asset)
	if err == nil {
		t.Fatal("挂靠节点已不存在，锚定该失败")
	}
	if errors.Is(err, ErrDanglingAnchor) {
		t.Fatalf("不该误报成 asset 不存在: %v", err)
	}
	if !errors.Is(err, ErrMissingAnchorOwner) {
		t.Fatalf("该报成挂靠节点不存在，实际 %v", err)
	}
	var owner *MissingAnchorOwnerError
	if !errors.As(err, &owner) || owner.NodeID != nodeID {
		t.Fatalf("该带上缺失的节点 id: %v", err)
	}
}

// TestAnchorDeleteBetweenPrecheckAndInsert 覆盖去掉 FOR SHARE 之后的那段窗口：校验
// 通过后、写入前资产被并发删掉，外键会拒绝，而调用方拿到的仍须是同一个一致性错误。
func TestAnchorDeleteBetweenPrecheckAndInsert(t *testing.T) {
	d := reliabilityTestDB(t)
	task := newReliabilityTask(t, d, "校验到写入之间被删-"+t.Name())
	asset := newReliabilityAsset(t, d, task.ID)
	store := d.Exploration(task.ExplorationID)
	ctx := context.Background()

	nodeID, err := store.AddFactCtx(ctx, map[string]any{"text": "owner"}, "test", nil, 0)
	if err != nil {
		t.Fatalf("建节点失败: %v", err)
	}

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("开事务失败: %v", err)
	}
	defer tx.Rollback()

	// ① 校验此刻通过（asset 还在）。
	if err := checkAnchorAssets(ctx, tx, d.Health(), task.ExplorationID, []int64{asset}); err != nil {
		t.Fatalf("校验此刻不该失败: %v", err)
	}

	// ② 另一条连接把它删掉——不加 FOR SHARE 正是为了让这一步不被阻塞（否则会与
	//    DeleteTaskCascadePrepared 的加锁顺序相反而死锁）。
	if _, err := d.Exec(`DELETE FROM assets WHERE id=$1`, asset); err != nil {
		t.Fatalf("并发删除失败（不该被阻塞）: %v", err)
	}

	// ③ 写入被外键拒绝，且翻译成 DanglingAnchorError。
	_, execErr := tx.ExecContext(ctx, `INSERT INTO exploration_anchors(node_id, asset_id) VALUES ($1,$2)`, nodeID, asset)
	if execErr == nil {
		t.Fatal("asset 已被删除，锚点写入该被外键拒绝")
	}
	mapped := anchorWriteErr(execErr, d.Health(), task.ExplorationID, nodeID, []int64{asset})
	if !errors.Is(mapped, ErrDanglingAnchor) {
		t.Fatalf("该翻译成悬空锚点错误，实际 %v", mapped)
	}
	if snap := d.Health().Snapshot(task.ExplorationID); snap.DanglingAnchors == 0 {
		t.Fatalf("该登记进健康表: %+v", snap)
	}
}

// TestDevBuildWithoutCommitIsNotRecorded 覆盖评审第 3 条：plain go build / dev.sh 的
// go run 都落到 "dev"，它指不回任何一次提交，不该被读成「记录过」；只有同时记到
// build_commit 时才算证据。
func TestDevBuildWithoutCommitIsNotRecorded(t *testing.T) {
	if provenanceRecorded(DevBuildVersion, map[string]any{"build_commit_source": "unknown"}) {
		t.Fatal("没有提交证据的 dev 不该算记录过")
	}
	if provenanceRecorded(DevBuildVersion, nil) {
		t.Fatal("没有 runtime 的 dev 不该算记录过")
	}
	if !provenanceRecorded(DevBuildVersion, map[string]any{"build_commit": "f33e81bfbaca639dbbaf263786841052a6681cc4"}) {
		t.Fatal("带提交 SHA 的 dev 应算记录过")
	}
	if provenanceRecorded(LegacyUnknownBuild, map[string]any{"build_commit": "abc"}) {
		t.Fatal("legacy 哨兵永远不算记录过")
	}
	if !provenanceRecorded("0.4.3", nil) {
		t.Fatal("正式版本号应算记录过")
	}
}

// TestProbeErrorDoesNotLeakDSNPassword 是评审第 1 条（阻塞项）的回归测试，不需要活库：
// 一条带查询串口令、且 sslmode 非法的 URL 会在连接之前就被 pgx 拒绝，而 pgx 的解析错误
// 把整条 DSN 嵌进 message，且只打码 URL userinfo 与 libpq 键值形态。实测 `?password=`
// 与 `?sslpassword=` 原样输出，再经 artex doctor 打印、或 log.Fatalf("open stores: %v")
// 落进日志。连接路径的错误必须先过 ScrubSecrets。
func TestProbeErrorDoesNotLeakDSNPassword(t *testing.T) {
	const canary = "PW-LEAK-CANARY"
	for _, dsn := range []string{
		"postgres://artex@127.0.0.1:1/artex?password=" + canary + "&sslmode=bogus-tls-mode",
		"postgres://artex@127.0.0.1:1/artex?sslpassword=" + canary + "&sslmode=bogus-tls-mode",
		"postgres://artex:" + canary + "@127.0.0.1:1/artex?sslmode=bogus-tls-mode",
		"host=127.0.0.1 port=1 user=artex password=" + canary + " sslmode=bogus-tls-mode",
	} {
		_, err := Probe(dsn)
		if err == nil {
			t.Fatalf("sslmode 非法，该在连接前就失败: %s", strings.ReplaceAll(dsn, canary, "<PW>"))
		}
		if strings.Contains(err.Error(), canary) {
			t.Fatalf("连接错误泄露了口令原文:\n  %v", err)
		}
	}
}
