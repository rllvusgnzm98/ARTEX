package db

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"testing"
)

func openInheritDB(t *testing.T) (*DB, *CredentialStore) {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { d.Close() })
	return d, NewCredentialStore(d, []byte("test-jwt-key-material-32bytes!!!"))
}

func inheritTasks(t *testing.T, d *DB) (parent, child int64) {
	t.Helper()
	p, err := d.CreateTask(t.Name()+" parent", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.CreateTask(t.Name()+" child", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent, child = p.ID, c.ID
	t.Cleanup(func() {
		_ = d.DeleteTask(child)
		_ = d.DeleteTask(parent)
	})
	return parent, child
}

func mustInheritCred(t *testing.T, store *CredentialStore, rec *CredentialRecord) int64 {
	t.Helper()
	id, err := store.Create(context.Background(), rec)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = store.Delete(context.Background(), id) })
	return id
}

func inheritCount(t *testing.T, d *DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := d.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestInheritSchemaHasNoSecret(t *testing.T) {
	d, _ := openInheritDB(t)
	var secretCols int
	if err := d.QueryRow(`SELECT count(*) FROM information_schema.columns
WHERE table_schema='public' AND table_name='credential_inheritances' AND column_name='secret'`).Scan(&secretCols); err != nil {
		t.Fatal(err)
	}
	if secretCols != 0 {
		t.Fatal("credential_inheritances 不得存 secret")
	}
	var def string
	if err := d.QueryRow(`SELECT indexdef FROM pg_indexes
WHERE schemaname='public' AND indexname='idx_credential_inheritances_child_active'`).Scan(&def); err != nil {
		t.Fatalf("缺少 child_task_id 的 active 部分索引: %v", err)
	}
	low := strings.ToLower(def)
	if !strings.Contains(low, "child_task_id") || !strings.Contains(low, "active") {
		t.Fatalf("部分索引定义不对: %s", def)
	}
	if inheritCount(t, d, `SELECT count(*) FROM pg_indexes WHERE schemaname='public' AND indexname='idx_credential_inheritances_credential'`) != 1 {
		t.Fatal("缺少 credential_id 索引")
	}
	if inheritCount(t, d, `SELECT count(*) FROM pg_constraint
WHERE conrelid='credential_inheritances'::regclass AND contype='f' AND confdeltype='c'`) != 3 {
		t.Fatal("child/source/credential 三条外键都应是 ON DELETE CASCADE")
	}
}

func TestInheritIdempotentUpdatesScore(t *testing.T) {
	d, store := openInheritDB(t)
	parent, child := inheritTasks(t, d)
	ctx := context.Background()
	credID := mustInheritCred(t, store, &CredentialRecord{
		TaskID: parent, Username: "fixture-admin", CredType: CredPassword,
		Secret: fixturePass, Source: "fixture",
	})
	first := CredentialInheritance{
		ChildTaskID: child, SourceTaskID: parent, CredentialID: credID,
		ScopeBasis: InheritCompany, Score: 10, Reason: "low",
	}
	if err := store.Inherit(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := store.Inherit(ctx, first); err != nil {
		t.Fatal(err)
	}
	if n := inheritCount(t, d, `SELECT count(*) FROM credential_inheritances WHERE child_task_id=$1 AND credential_id=$2`, child, credID); n != 1 {
		t.Fatalf("重复 Inherit 应保持 1 行, got %d", n)
	}
	var basis, reason string
	var score float64
	if err := d.QueryRow(`SELECT scope_basis, score, reason FROM credential_inheritances WHERE child_task_id=$1 AND credential_id=$2`, child, credID).Scan(&basis, &score, &reason); err != nil {
		t.Fatal(err)
	}
	if basis != InheritCompany || score != 10 || reason != "low" {
		t.Fatalf("初次写入 = %s %v %s", basis, score, reason)
	}

	if err := store.Inherit(ctx, CredentialInheritance{
		ChildTaskID: child, SourceTaskID: parent, CredentialID: credID,
		ScopeBasis: InheritFootholdHost, Score: 40, Reason: "high",
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT scope_basis, score, reason FROM credential_inheritances WHERE child_task_id=$1 AND credential_id=$2`, child, credID).Scan(&basis, &score, &reason); err != nil {
		t.Fatal(err)
	}
	if basis != InheritFootholdHost || score != 40 || reason != "high" {
		t.Fatalf("更高分应覆盖: %s %v %s", basis, score, reason)
	}
	if n := inheritCount(t, d, `SELECT count(*) FROM credential_inheritances WHERE child_task_id=$1 AND credential_id=$2`, child, credID); n != 1 {
		t.Fatalf("更新后仍应是 1 行, got %d", n)
	}
}

func TestInheritKeepsHighestScore(t *testing.T) {
	d, store := openInheritDB(t)
	parent, child := inheritTasks(t, d)
	ctx := context.Background()
	credID := mustInheritCred(t, store, &CredentialRecord{
		TaskID: parent, Username: "fixture-admin", CredType: CredPassword,
		Secret: fixturePass, Source: "fixture",
	})
	if err := store.Inherit(ctx, CredentialInheritance{
		ChildTaskID: child, SourceTaskID: parent, CredentialID: credID,
		ScopeBasis: InheritFootholdHost, Score: 40, Reason: "best",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Inherit(ctx, CredentialInheritance{
		ChildTaskID: child, SourceTaskID: parent, CredentialID: credID,
		ScopeBasis: InheritFootholdHost, Score: 40, Reason: "same",
	}); err != nil {
		t.Fatal(err)
	}
	var basis, reason string
	var score float64
	if err := d.QueryRow(`SELECT scope_basis, score, reason FROM credential_inheritances WHERE child_task_id=$1 AND credential_id=$2`, child, credID).Scan(&basis, &score, &reason); err != nil {
		t.Fatal(err)
	}
	if score != 40 || basis != InheritFootholdHost || reason != "same" {
		t.Fatalf("同分应允许刷新 basis/reason: %s %v %s", basis, score, reason)
	}
	if err := store.Inherit(ctx, CredentialInheritance{
		ChildTaskID: child, SourceTaskID: parent, CredentialID: credID,
		ScopeBasis: InheritCompany, Score: 10, Reason: "worse",
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT scope_basis, score, reason FROM credential_inheritances WHERE child_task_id=$1 AND credential_id=$2`, child, credID).Scan(&basis, &score, &reason); err != nil {
		t.Fatal(err)
	}
	if score != 40 || basis != InheritFootholdHost || reason != "same" {
		t.Fatalf("较低分不得覆盖更高分: %s %v %s", basis, score, reason)
	}
}

func TestInheritRevokedDoesNotRevive(t *testing.T) {
	d, store := openInheritDB(t)
	parent, child := inheritTasks(t, d)
	ctx := context.Background()
	credID := mustInheritCred(t, store, &CredentialRecord{
		TaskID: parent, Username: "fixture-admin", CredType: CredPassword,
		Secret: fixturePass, Domain: "FIXTURE", Source: "fixture",
	})
	ownID := mustInheritCred(t, store, &CredentialRecord{
		TaskID: child, Username: "child-own", CredType: CredPassword,
		Secret: "child-own-fixture", Source: "fixture",
	})
	if err := store.Inherit(ctx, CredentialInheritance{
		ChildTaskID: child, SourceTaskID: parent, CredentialID: credID,
		ScopeBasis: InheritDomain, Score: 20, Reason: "domain",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeInherited(ctx, child, credID); err != nil {
		t.Fatal(err)
	}
	var state string
	var revoked bool
	var score float64
	if err := d.QueryRow(`SELECT state, revoked_at IS NOT NULL, score FROM credential_inheritances WHERE child_task_id=$1 AND credential_id=$2`, child, credID).Scan(&state, &revoked, &score); err != nil {
		t.Fatal(err)
	}
	if state != InheritRevoked || !revoked || score != 20 {
		t.Fatalf("撤销后应保持 revoked, got %s revoked=%v score=%v", state, revoked, score)
	}
	err := store.Inherit(ctx, CredentialInheritance{
		ChildTaskID: child, SourceTaskID: parent, CredentialID: credID,
		ScopeBasis: InheritFootholdHost, Score: 99, Reason: "revive",
	})
	if !errors.Is(err, ErrInheritanceRevoked) {
		t.Fatalf("撤销后 Inherit 应返回 ErrInheritanceRevoked, got %v", err)
	}
	if err := d.QueryRow(`SELECT state, score FROM credential_inheritances WHERE child_task_id=$1 AND credential_id=$2`, child, credID).Scan(&state, &score); err != nil {
		t.Fatal(err)
	}
	if state != InheritRevoked || score != 20 {
		t.Fatalf("撤销行被复活: state=%s score=%v", state, score)
	}
	if err := store.RevokeInherited(ctx, child, credID); err == nil {
		t.Fatal("重复撤销应报错")
	}
	if err := store.RevokeInherited(ctx, child, credID+999999); err == nil {
		t.Fatal("不存在的继承应报错")
	}

	list, err := store.ListInherited(ctx, child)
	if err != nil {
		t.Fatal(err)
	}
	foundOwn := false
	for _, item := range list.Items {
		if item.ID == credID {
			t.Fatalf("撤销后列表不应含该凭据: %+v", item)
		}
		if item.ID == ownID {
			foundOwn = true
			if item.Inherited || item.Secret != "child-own-fixture" {
				t.Fatalf("自有凭据应保留且不标继承: %+v", item)
			}
		}
	}
	if !foundOwn {
		t.Fatal("撤销继承不应丢掉子任务自有凭据")
	}
	meta, err := store.ListInheritedMeta(ctx, child)
	if err != nil {
		t.Fatal(err)
	}
	if len(meta) != 0 {
		t.Fatalf("撤销后元数据应为空: %+v", meta)
	}
}

func TestListInheritedSkipsUndecryptable(t *testing.T) {
	d, good := openInheritDB(t)
	other := NewCredentialStore(d, []byte("another-master-key-32bytes!!!!"))
	parent, child := inheritTasks(t, d)
	ctx := context.Background()
	goodID := mustInheritCred(t, good, &CredentialRecord{
		TaskID: parent, Username: "fixture-admin", CredType: CredPassword,
		Secret: fixturePass, Source: "fixture",
	})
	badID := mustInheritCred(t, other, &CredentialRecord{
		TaskID: parent, Username: "other", CredType: CredPassword,
		Secret: "fixture-cannot-decrypt", Source: "fixture",
	})
	ownID := mustInheritCred(t, good, &CredentialRecord{
		TaskID: child, Username: "child-own", CredType: CredPassword,
		Secret: "child-own-fixture", Source: "fixture",
	})
	for _, id := range []int64{goodID, badID} {
		if err := good.Inherit(ctx, CredentialInheritance{
			ChildTaskID: child, SourceTaskID: parent, CredentialID: id,
			ScopeBasis: InheritSameSegment, Score: 30, Reason: "seg",
		}); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	list, err := good.ListInherited(ctx, child)
	if err != nil {
		t.Fatalf("解密失败不得让整表失败: %v", err)
	}
	seen := map[int64]*CredentialRecord{}
	for _, item := range list.Items {
		seen[item.ID] = item
	}
	if seen[badID] != nil {
		t.Fatal("无法解密的继承行不得进入 Items")
	}
	if seen[goodID] == nil || !seen[goodID].Inherited || seen[goodID].Secret != fixturePass ||
		seen[goodID].SourceTaskID != parent || seen[goodID].ScopeBasis != InheritSameSegment {
		t.Fatalf("可解继承行不对: %+v", seen[goodID])
	}
	if seen[ownID] == nil || seen[ownID].Inherited || seen[ownID].ScopeBasis != "" {
		t.Fatalf("自有行不应标成继承: %+v", seen[ownID])
	}
	if len(list.Skipped) != 1 || list.Skipped[0] != badID {
		t.Fatalf("Skipped = %+v, 应只有 %d", list.Skipped, badID)
	}
	logs := buf.String()
	if strings.Contains(logs, fixturePass) || strings.Contains(logs, "fixture-cannot-decrypt") || strings.Contains(logs, secretPrefix) {
		t.Fatalf("跳过日志不得含口令或密文: %s", logs)
	}

	meta, err := good.ListInheritedMeta(ctx, child)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, fixturePass) || strings.Contains(text, "fixture-cannot-decrypt") ||
		strings.Contains(text, "child-own-fixture") || strings.Contains(text, `"secret"`) {
		t.Fatalf("元数据不得含 secret: %s", text)
	}
	foundGood, foundBad := false, false
	for _, m := range meta {
		if m.CredentialID == goodID {
			foundGood = true
			if m.Username != "fixture-admin" || m.CredType != CredPassword || m.SourceTaskID != parent || m.ScopeBasis != InheritSameSegment {
				t.Fatalf("元数据字段不对: %+v", m)
			}
		}
		if m.CredentialID == badID {
			foundBad = true
		}
		if m.CredentialID == ownID {
			t.Fatal("元数据不应包含子任务自有凭据")
		}
	}
	if !foundGood || !foundBad {
		t.Fatalf("元数据应含可解与不可解继承行(仍不含 secret): %+v", meta)
	}
	var blob string
	if err := d.QueryRow(`SELECT credential_inheritances::text FROM credential_inheritances WHERE credential_id=$1`, goodID).Scan(&blob); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(blob, fixturePass) {
		t.Fatalf("继承行落库了 secret: %s", blob)
	}
}

func TestInheritRemovedWhenCredentialOrTaskDeleted(t *testing.T) {
	d, store := openInheritDB(t)
	ctx := context.Background()

	t.Run("credential", func(t *testing.T) {
		parent, child := inheritTasks(t, d)
		credID := mustInheritCred(t, store, &CredentialRecord{
			TaskID: parent, Username: "fixture-admin", CredType: CredPassword,
			Secret: fixturePass, Source: "fixture",
		})
		if err := store.Inherit(ctx, CredentialInheritance{
			ChildTaskID: child, SourceTaskID: parent, CredentialID: credID,
			ScopeBasis: InheritCompany, Score: 10,
		}); err != nil {
			t.Fatal(err)
		}
		if err := store.Delete(ctx, credID); err != nil {
			t.Fatal(err)
		}
		if n := inheritCount(t, d, `SELECT count(*) FROM credential_inheritances WHERE credential_id=$1`, credID); n != 0 {
			t.Fatalf("凭据删除后继承行残留 %d", n)
		}
		list, err := store.ListInherited(ctx, child)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range list.Items {
			if item.ID == credID {
				t.Fatal("凭据删除后 ListInherited 仍可见")
			}
		}
	})

	t.Run("child task", func(t *testing.T) {
		parent, child := inheritTasks(t, d)
		credID := mustInheritCred(t, store, &CredentialRecord{
			TaskID: parent, Username: "fixture-admin", CredType: CredPassword,
			Secret: fixturePass, Source: "fixture",
		})
		if err := store.Inherit(ctx, CredentialInheritance{
			ChildTaskID: child, SourceTaskID: parent, CredentialID: credID,
			ScopeBasis: InheritSameSegment, Score: 30,
		}); err != nil {
			t.Fatal(err)
		}
		if err := d.DeleteTask(child); err != nil {
			t.Fatalf("删除子任务: %v", err)
		}
		if n := inheritCount(t, d, `SELECT count(*) FROM credential_inheritances WHERE child_task_id=$1 OR credential_id=$2`, child, credID); n != 0 {
			t.Fatalf("子任务删除后继承行残留 %d", n)
		}
		if got, err := store.Get(ctx, credID); err != nil || got == nil {
			t.Fatalf("删除子任务不应删掉凭据: %v %+v", err, got)
		}
		if inheritCount(t, d, `SELECT count(*) FROM tasks WHERE id=$1`, parent) != 1 {
			t.Fatal("父任务应还在")
		}
	})

	t.Run("parent task", func(t *testing.T) {
		parent, child := inheritTasks(t, d)
		credID := mustInheritCred(t, store, &CredentialRecord{
			TaskID: parent, Username: "fixture-admin", CredType: CredPassword,
			Secret: fixturePass, Source: "fixture",
		})
		if err := store.Inherit(ctx, CredentialInheritance{
			ChildTaskID: child, SourceTaskID: parent, CredentialID: credID,
			ScopeBasis: InheritFootholdHost, Score: 40,
		}); err != nil {
			t.Fatal(err)
		}
		if err := d.DeleteTask(parent); err != nil {
			t.Fatalf("删除父任务: %v", err)
		}
		if n := inheritCount(t, d, `SELECT count(*) FROM credential_inheritances WHERE source_task_id=$1 OR credential_id=$2`, parent, credID); n != 0 {
			t.Fatalf("父任务删除后继承行残留 %d", n)
		}
		if got, err := store.Get(ctx, credID); err != nil || got == nil {
			t.Fatalf("删除父任务不应连带删除凭据(credentials.task_id 无 FK): %v %+v", err, got)
		}
		list, err := store.ListInherited(ctx, child)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range list.Items {
			if item.ID == credID {
				t.Fatal("父任务删除后子任务不应再看见继承凭据")
			}
		}
		if inheritCount(t, d, `SELECT count(*) FROM tasks WHERE id=$1`, child) != 1 {
			t.Fatal("子任务应还在")
		}
	})
}
