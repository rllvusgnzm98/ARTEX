package server

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/guard"
)

// 批 5 B2:dsnPassword 从两种 DSN 形态提取密码(URL / keyword),无密码返回空。
func TestDSNPassword(t *testing.T) {
	cases := []struct {
		dsn, want string
	}{
		{"postgres://artex:s3cr3t@127.0.0.1:5432/artex?sslmode=disable", "s3cr3t"},
		{"postgres://artex@127.0.0.1:5432/artex", ""},
		{"host=127.0.0.1 user=artex password=pw123456 dbname=artex", "pw123456"},
		{"host=127.0.0.1 password='pw with space' dbname=artex", "pw with space"},
		{"host=127.0.0.1 dbname=artex", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := dsnPassword(c.dsn); got != c.want {
			t.Errorf("dsnPassword(%q) = %q, want %q", c.dsn, got, c.want)
		}
	}
}

// 批 5 B4:uaForTask 在无 DB 时用默认池,且同任务稳定(有 DB 的路径依赖 PG,
// 由集成环境覆盖,单测不打 DSN)。
func TestUAForTaskDefaultPool(t *testing.T) {
	s := &Server{} // m == nil → 默认池
	ua := s.uaForTask(42)
	if ua == "" {
		t.Fatal("uaForTask should return a default-pool UA without a DB")
	}
	if got := s.uaForTask(42); got != ua {
		t.Fatalf("same task must keep the same UA: %q vs %q", ua, got)
	}
	pool := agent.DefaultUAPool()
	found := false
	for _, p := range pool {
		if p == ua {
			found = true
		}
	}
	if !found {
		t.Fatalf("uaForTask without settings should pick from the default pool, got %q", ua)
	}
}

// 阶段 B1:注册后平台自身 host 进入 EgressGuard；callback 主机、监听 host、
// 配置 own_infra_hosts 与回环地址都认。
func TestRegisterEgressOwnInfra(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfg, []byte(`{"own_infra_hosts":["CDN.Example.COM.","192.0.2.10"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_CONFIG", cfg)
	t.Setenv("ARTEX_CALLBACK_ADDR", "203.0.113.50:4444")
	config.SetListenAddr("192.0.2.10:9090")
	t.Cleanup(func() { config.SetListenAddr("") })

	wantHosts := []string{"203.0.113.50", "192.0.2.10", "cdn.example.com", "127.0.0.1", "::1", "localhost"}
	if got := config.OwnInfraHosts(); !reflect.DeepEqual(got, wantHosts) {
		t.Fatalf("OwnInfraHosts = %#v, want %#v", got, wantHosts)
	}
	if config.OwnInfraPort() != 9090 {
		t.Fatalf("OwnInfraPort = %d, want 9090", config.OwnInfraPort())
	}

	s := &Server{m: &Manager{egress: guard.NewEgressGuard()}}
	s.registerEgressFingerprints()
	eg := s.m.egress
	for _, h := range []string{"203.0.113.50", "192.0.2.10:1", "CDN.Example.COM", "127.0.0.1", "localhost", "[::1]"} {
		if !eg.IsOwnInfraHost(h) {
			t.Fatalf("own infra missing %q", h)
		}
	}
	if eg.IsOwnInfraHost("evil.example") {
		t.Fatal("third party must not be own infra")
	}
	kinds := eg.CheckKinds("203.0.113.50:4444")
	found := false
	for _, k := range kinds {
		if k == "callback_addr" {
			found = true
		}
	}
	if !found {
		t.Fatalf("callback fingerprint missing, kinds=%v", kinds)
	}

	config.SetListenAddr("[::1]:8787")
	// 监听 host ::1 提前出现，与末尾回环去重；配置里的 192.0.2.10 仍在。
	deduped := []string{"203.0.113.50", "::1", "cdn.example.com", "192.0.2.10", "127.0.0.1", "localhost"}
	if got := config.OwnInfraHosts(); !reflect.DeepEqual(got, deduped) {
		t.Fatalf("deduped OwnInfraHosts = %#v, want %#v", got, deduped)
	}
	if config.OwnInfraPort() != 8787 {
		t.Fatalf("ipv6 listen port = %d, want 8787", config.OwnInfraPort())
	}
	config.SetListenAddr(":8787")
	if config.OwnInfraPort() != 8787 {
		t.Fatalf("wildcard listen port = %d, want 8787", config.OwnInfraPort())
	}
	for _, h := range config.OwnInfraHosts() {
		if h == "" {
			t.Fatal("wildcard listen must not add an empty host")
		}
	}
	config.SetListenAddr("not-a-port")
	if config.OwnInfraPort() != 0 {
		t.Fatalf("unparseable listen port = %d, want 0", config.OwnInfraPort())
	}
}

// 阶段 B1:过短的 callback_addr 跳过指纹注册且不 panic，日志不含原文。
func TestRegisterEgressShortCallbackSkipped(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfg, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_CONFIG", cfg)
	const short = "cb:1"
	t.Setenv("ARTEX_CALLBACK_ADDR", short)
	config.SetListenAddr(":8787")
	t.Cleanup(func() { config.SetListenAddr("") })

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	s := &Server{m: &Manager{egress: guard.NewEgressGuard()}}
	s.registerEgressFingerprints()

	logged := buf.String()
	if strings.Contains(logged, short) {
		t.Fatalf("diagnostic log echoed callback: %s", logged)
	}
	if !strings.Contains(logged, "不足") || !strings.Contains(logged, "跳过") {
		t.Fatalf("expected length diagnostic, got %q", logged)
	}
	for _, k := range s.m.egress.CheckKinds("xx" + short + "yy") {
		if k == "callback_addr" {
			t.Fatal("short callback must not be fingerprinted")
		}
	}
	if !s.m.egress.IsOwnInfraHost("127.0.0.1") || !s.m.egress.IsOwnInfraHost("cb") {
		t.Fatal("own infra should still be registered when callback is too short to fingerprint")
	}
	if config.OwnInfraPort() != 8787 {
		t.Fatalf("port = %d, want 8787", config.OwnInfraPort())
	}
}
