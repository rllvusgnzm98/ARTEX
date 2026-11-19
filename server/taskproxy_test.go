package server

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/tunnel"
)

// fakeTunnelLister 按 taskID 注入假台账（测试不得部署真实隧道）。
type fakeTunnelLister struct {
	byTask map[int64][]*db.TunnelRecord
	err    error
	recs   []*db.TunnelRecord // 兼容单任务用例：忽略 taskID
}

func (f *fakeTunnelLister) ListByTask(_ context.Context, taskID int64) ([]*db.TunnelRecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.byTask != nil {
		return f.byTask[taskID], nil
	}
	return f.recs, nil
}

func socksRec(id int64, state string, socksPort int) *db.TunnelRecord {
	raw, _ := json.Marshal(tunnel.Plan{Kind: tunnel.KindSocks, SocksPort: socksPort})
	return &db.TunnelRecord{ID: id, Kind: tunnel.KindSocks, State: state, DeployParams: raw}
}

func suo5Rec(id int64, state string, socksPort int) *db.TunnelRecord {
	raw, _ := json.Marshal(tunnel.Plan{Kind: tunnel.KindSocks, SocksPort: socksPort, AuthUser: "artex", AuthPass: "fixture-pass"})
	return &db.TunnelRecord{ID: id, Kind: tunnel.KindSocks, Adapter: tunnel.AdapterSuo5, State: state, DeployParams: raw}
}

func TestPickUpstream(t *testing.T) {
	const global = "http://127.0.0.1:9000"
	cases := []struct {
		name string
		recs []*db.TunnelRecord
		want string
	}{
		{"无隧道回落全局", nil, global},
		{"alive socks 当选", []*db.TunnelRecord{socksRec(1, db.TunnelAlive, 20801)}, "socks5://127.0.0.1:20801"},
		{"多条取 id 最大", []*db.TunnelRecord{
			socksRec(1, db.TunnelAlive, 20801), socksRec(3, db.TunnelAlive, 20803), socksRec(2, db.TunnelAlive, 20802),
		}, "socks5://127.0.0.1:20803"},
		{"error/stopped 不算", []*db.TunnelRecord{
			socksRec(1, db.TunnelError, 20801), socksRec(2, db.TunnelStopped, 20802),
		}, global},
		{"portfwd 不是上游", []*db.TunnelRecord{{
			ID: 1, Kind: tunnel.KindPortfwd, State: db.TunnelAlive,
			DeployParams: json.RawMessage(`{"kind":"portfwd","local_port":20810}`),
		}}, global},
		{"deploy_params 缺 socks_port 跳过", []*db.TunnelRecord{
			{ID: 1, Kind: tunnel.KindSocks, State: db.TunnelAlive, DeployParams: json.RawMessage(`{}`)},
		}, global},
		{"suo5 上游内嵌 auth", []*db.TunnelRecord{suo5Rec(9, db.TunnelAlive, 20809)}, "socks5://artex:fixture-pass@127.0.0.1:20809"},
	}
	for _, c := range cases {
		if got := pickUpstream(c.recs, global); got != c.want {
			t.Errorf("%s: pickUpstream = %q, want %q", c.name, got, c.want)
		}
	}
	if got := pickUpstream(nil, ""); got != "" {
		t.Errorf("无隧道+无全局代理应为直连(空), got %q", got)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("找空闲端口: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func managedPortRegistered(port int) bool {
	_, ok := dynManagedPorts.Load(port)
	return ok
}

func TestTaskProxyLifecycle(t *testing.T) {
	port := freePort(t)
	lister := &fakeTunnelLister{}
	m := newTaskProxyManager(t.TempDir(), lister, func() string { return "http://127.0.0.1:9000" }, port, port)
	ctx := context.Background()

	addr, ca := m.ForTask(ctx, 42)
	if addr == "" || ca == "" {
		t.Fatalf("ForTask 应返回实例地址与 CA, got (%q, %q)", addr, ca)
	}
	if !strings.Contains(addr, ":"+strconv.Itoa(port)) {
		t.Errorf("实例地址应含分配端口 %d: %s", port, addr)
	}
	if _, err := os.Stat(ca); err != nil {
		t.Errorf("实例 CA 证书应已落盘 %s: %v", ca, err)
	}
	if !managedPortRegistered(port) {
		t.Error("实例端口应登记")
	}
	inst := m.proxies[42]
	if inst == nil {
		t.Fatal("实例应已入表")
	}
	if got := inst.tr.UpstreamProxy(); got != "http://127.0.0.1:9000" {
		t.Errorf("无隧道时上游应回落全局代理, got %q", got)
	}

	addr2, _ := m.ForTask(ctx, 42)
	if addr2 != addr {
		t.Errorf("重复 ForTask 不应重建实例: %q → %q", addr, addr2)
	}

	lister.recs = []*db.TunnelRecord{socksRec(7, db.TunnelAlive, 20807)}
	m.Refresh(ctx, 42)
	if got := inst.tr.UpstreamProxy(); got != "socks5://127.0.0.1:20807" {
		t.Errorf("隧道 alive 后上游应热切换, got %q", got)
	}

	lister.recs = []*db.TunnelRecord{socksRec(7, db.TunnelError, 20807)}
	m.Refresh(ctx, 42)
	if got := inst.tr.UpstreamProxy(); got != "http://127.0.0.1:9000" {
		t.Errorf("隧道死亡后上游应回落全局代理, got %q", got)
	}

	m.Refresh(ctx, 99)
	if m.proxies[99] != nil {
		t.Error("Refresh 不应为无实例任务建实例(懒建语义)")
	}

	m.CloseTask(42)
	if managedPortRegistered(port) {
		t.Error("CloseTask 后端口应注销")
	}
	if m.proxies[42] != nil {
		t.Error("CloseTask 后实例应出表")
	}
	if _, err := os.Stat(ca); err != nil {
		t.Errorf("CloseTask 后 CA 目录应保留(留痕), stat %s: %v", ca, err)
	}
	m.CloseTask(42)

	addr3, _ := m.ForTask(ctx, 42)
	if addr3 == "" {
		t.Fatal("CloseTask 后应能重新懒建实例")
	}
	m.Close()
	if managedPortRegistered(port) {
		t.Error("Close 后端口应全部注销")
	}
}

// TestTwoTasksDoNotStompUpstream 两个任务各自的 MITM 上游不得互相踩踏。
func TestTwoTasksDoNotStompUpstream(t *testing.T) {
	portA := freePort(t)
	portB := freePort(t)
	if portA == portB {
		t.Fatal("需要两个不同空闲端口")
	}
	min, max := portA, portB
	if min > max {
		min, max = max, min
	}
	lister := &fakeTunnelLister{byTask: map[int64][]*db.TunnelRecord{
		11: {socksRec(1, db.TunnelAlive, 20811)},
		22: {socksRec(2, db.TunnelAlive, 20822)},
	}}
	m := newTaskProxyManager(t.TempDir(), lister, func() string { return "http://127.0.0.1:9000" }, min, max)
	ctx := context.Background()
	defer m.Close()

	addrA, _ := m.ForTask(ctx, 11)
	addrB, _ := m.ForTask(ctx, 22)
	if addrA == "" || addrB == "" || addrA == addrB {
		t.Fatalf("两任务应各自拿到不同 MITM 地址: %q / %q", addrA, addrB)
	}
	instA, instB := m.proxies[11], m.proxies[22]
	if instA == nil || instB == nil {
		t.Fatal("两任务实例都应入表")
	}
	if got := instA.tr.UpstreamProxy(); got != "socks5://127.0.0.1:20811" {
		t.Errorf("任务 11 上游不符: %q", got)
	}
	if got := instB.tr.UpstreamProxy(); got != "socks5://127.0.0.1:20822" {
		t.Errorf("任务 22 上游不符: %q", got)
	}

	// 只改任务 11 的台账，任务 22 的上游必须保持不变。
	lister.byTask[11] = []*db.TunnelRecord{socksRec(3, db.TunnelAlive, 20813)}
	m.Refresh(ctx, 11)
	if got := instA.tr.UpstreamProxy(); got != "socks5://127.0.0.1:20813" {
		t.Errorf("任务 11 热切换后上游不符: %q", got)
	}
	if got := instB.tr.UpstreamProxy(); got != "socks5://127.0.0.1:20822" {
		t.Errorf("任务 22 上游被踩踏: %q", got)
	}

	lister.byTask[11] = nil
	m.Refresh(ctx, 11)
	if got := instA.tr.UpstreamProxy(); got != "http://127.0.0.1:9000" {
		t.Errorf("任务 11 无隧道应回落全局: %q", got)
	}
	if got := instB.tr.UpstreamProxy(); got != "socks5://127.0.0.1:20822" {
		t.Errorf("任务 22 上游在任务 11 回落后被踩踏: %q", got)
	}
}
