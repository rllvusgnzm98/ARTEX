package db

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
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
	defer admin.Close()
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
		_, _ = admin.Exec(`DROP DATABASE IF EXISTS ` + pqIdent(name))
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

func TestProbeUnreachable(t *testing.T) {
	_, err := Probe("postgres://artex@127.0.0.1:1/definitely_not_listening?sslmode=disable")
	if err == nil {
		t.Fatal("不可达实例应返回错误")
	}
}
