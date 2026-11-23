package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func TestProbeConnectsWithoutMigrating(t *testing.T) {
	dsn := testDSN(t)
	n, err := Probe(dsn)
	if err != nil {
		t.Fatalf("Probe 应能轻量 ping 已有库: %v", err)
	}
	_ = n
}

func TestProbeDoesNotCreateSchema(t *testing.T) {
	base := testDSN(t)
	u, err := url.Parse(base)
	if err != nil {
		t.Skip("DSN 不是 URL，跳过独立空库探测")
	}
	adminURL := *u
	adminURL.Path = "/postgres"
	admin, err := sql.Open("pgx", adminURL.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := admin.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := admin.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("artex_probe_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE `+pqIdent(name)); err != nil {
		t.Fatalf("无法创建一次性探测库: %v", err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(`DROP DATABASE IF EXISTS ` + pqIdent(name)); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})

	empty := *u
	empty.Path = "/" + name
	n, err := Probe(empty.String())
	if err != nil {
		t.Fatal("空库 Probe 应 ping 成功，不得走迁移")
	}
	if n >= 0 {
		t.Fatalf("表不存在时应返回 n<0, got %d", n)
	}

	probeDB, err := sql.Open("pgx", empty.String())
	if err != nil {
		t.Fatal(err)
	}
	defer probeDB.Close()
	var exists bool
	if err := probeDB.QueryRowContext(ctx, `SELECT to_regclass('public.llm_profiles') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("Probe 不得创建 llm_profiles / 不得走 Open 迁移")
	}
	if err := probeDB.QueryRowContext(ctx, `SELECT to_regclass('public.agents') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("Probe 不得跑 schema 迁移")
	}
}

func pqIdent(name string) string {
	return `"` + name + `"`
}

func TestProbeOtherQueryErrorIsNotUninitialized(t *testing.T) {
	base := testDSN(t)
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal("DSN 不是 URL，无法构造权限夹具（本用例在有 DSN 时必须 RAN）")
	}
	adminURL := *u
	adminURL.Path = "/postgres"
	admin, err := sql.Open("pgx", adminURL.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := admin.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := admin.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	dbName := "artex_probe_qe_" + suffix
	role := "artex_probe_ro_" + suffix
	// 夹具口令，不是真实秘密。
	rolePass := "fixture_no_select"
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE `+pqIdent(dbName)); err != nil {
		t.Fatalf("无法创建一次性探测库: %v", err)
	}
	if _, err := admin.ExecContext(ctx, `CREATE ROLE `+pqIdent(role)+` LOGIN PASSWORD '`+rolePass+`'`); err != nil {
		_, _ = admin.Exec(`DROP DATABASE IF EXISTS ` + pqIdent(dbName))
		t.Fatalf("无法创建只读角色: %v", err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(`DROP DATABASE IF EXISTS ` + pqIdent(dbName)); err != nil {
			t.Errorf("cleanup: %v", err)
		}
		if _, err := admin.Exec(`DROP ROLE IF EXISTS ` + pqIdent(role)); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})

	ownerURL := *u
	ownerURL.Path = "/" + dbName
	owner, err := sql.Open("pgx", ownerURL.String())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err := owner.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	stmts := []string{
		`CREATE TABLE llm_profiles (id int)`,
		`GRANT CONNECT ON DATABASE ` + pqIdent(dbName) + ` TO ` + pqIdent(role),
		`GRANT USAGE ON SCHEMA public TO ` + pqIdent(role),
		`REVOKE ALL ON TABLE llm_profiles FROM PUBLIC`,
		`REVOKE ALL ON TABLE llm_profiles FROM ` + pqIdent(role),
	}
	for _, s := range stmts {
		if _, err := owner.ExecContext(ctx, s); err != nil {
			t.Fatalf("准备权限夹具失败 (%s): %v", s, err)
		}
	}

	ro := *u
	ro.Path = "/" + dbName
	ro.User = url.UserPassword(role, rolePass)
	n, err := Probe(ro.String())
	if err == nil {
		t.Fatalf("权限不足时必须返回 error，不得再返回 (%d, nil) 被当成库未初始化", n)
	}
	var qe *ProbeQueryError
	if !errors.As(err, &qe) {
		t.Fatalf("其它查询错误应包装为 ProbeQueryError, got %T %v", err, err)
	}
	if n >= 0 {
		t.Fatalf("查询失败时 n 应为 -1, got %d", n)
	}
	if isUndefinedTable(err) {
		t.Fatal("权限错误不得被判成表不存在")
	}
}

func TestProbeUnreachable(t *testing.T) {
	_, err := Probe("postgres://artex@127.0.0.1:1/definitely_not_listening?sslmode=disable")
	if err == nil {
		t.Fatal("不可达实例应返回错误")
	}
}

func TestDatabaseFailureConnectionRefused(t *testing.T) {
	const fallback = "PostgreSQL connection failed"
	const refused = "PostgreSQL connection refused"
	windowsReason := fallback
	if runtime.GOOS == "windows" {
		windowsReason = refused
	}
	for _, tt := range []struct {
		name string
		code syscall.Errno
		want string
	}{
		{"portable", syscall.ECONNREFUSED, refused},
		{"winsock", 10061, windowsReason},
		{"win32", 1225, windowsReason},
		{"other", syscall.ECONNRESET, fallback},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opErr := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", tt.code)}
			err := errors.Join(errors.New("untrusted connection refused text"), opErr)
			if got := databaseFailure(err, fallback).Error(); got != tt.want {
				t.Errorf("databaseFailure = %q, want %q", got, tt.want)
			}
		})
	}
}
