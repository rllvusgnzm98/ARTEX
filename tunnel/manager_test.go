package tunnel

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

type memStore struct {
	mu   sync.Mutex
	next int64
	rows map[int64]*db.TunnelRecord
}

func newMemStore() *memStore {
	return &memStore{next: 1, rows: map[int64]*db.TunnelRecord{}}
}

func cloneRec(r *db.TunnelRecord) *db.TunnelRecord {
	if r == nil {
		return nil
	}
	c := *r
	if r.DeployParams != nil {
		c.DeployParams = append(json.RawMessage(nil), r.DeployParams...)
	}
	return &c
}

func (s *memStore) Create(_ context.Context, rec *db.TunnelRecord) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.next
	s.next++
	row := cloneRec(rec)
	row.ID = id
	if row.State == "" {
		row.State = db.TunnelDeploying
	}
	s.rows[id] = row
	return id, nil
}

func (s *memStore) Get(_ context.Context, id int64) (*db.TunnelRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneRec(s.rows[id]), nil
}

func (s *memStore) UpdateState(_ context.Context, id int64, state, errMsg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.rows[id]
	if r == nil {
		return nil
	}
	r.State = state
	r.Error = errMsg
	return nil
}

func (s *memStore) UpdateDeployParams(_ context.Context, id int64, remotePID int, params json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.rows[id]
	if r == nil {
		return nil
	}
	r.RemotePID = remotePID
	r.DeployParams = append(json.RawMessage(nil), params...)
	return nil
}

func (s *memStore) Delete(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rows, id)
	return nil
}

func (s *memStore) listLocked(keep func(*db.TunnelRecord) bool) []*db.TunnelRecord {
	out := []*db.TunnelRecord{}
	for _, r := range s.rows {
		if keep(r) {
			out = append(out, cloneRec(r))
		}
	}
	return out
}

func (s *memStore) ListByTask(_ context.Context, taskID int64) ([]*db.TunnelRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listLocked(func(r *db.TunnelRecord) bool { return r.TaskID == taskID }), nil
}

func (s *memStore) ListAlive(_ context.Context) ([]*db.TunnelRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listLocked(func(r *db.TunnelRecord) bool { return r.State == db.TunnelAlive }), nil
}

func (s *memStore) ListActive(_ context.Context) ([]*db.TunnelRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listLocked(func(r *db.TunnelRecord) bool {
		return r.State == db.TunnelDeploying || r.State == db.TunnelAlive || r.State == db.TunnelError
	}), nil
}

func (s *memStore) List(_ context.Context) ([]*db.TunnelRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listLocked(func(*db.TunnelRecord) bool { return true }), nil
}

func freeListenPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func buildStub(t *testing.T) string {
	t.Helper()
	name := "stublisten"
	if runtime.GOOS == "windows" {
		// Windows 的 os/exec 只接受 PATHEXT 扩展名，无后缀的 PE 会被当成找不到。
		name += ".exe"
	}
	out := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", out, "./testdata/stublisten")
	cmd.Dir = mustThisDir(t)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build stublisten: %v\n%s", err, b)
	}
	return out
}

func mustThisDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}

func socksPlan(taskID int64, socksPort, listenPort int) *Plan {
	return &Plan{
		Kind: KindSocks, Adapter: AdapterChisel, TaskID: taskID,
		ListenHost: "127.0.0.1", ListenPort: listenPort, SocksPort: socksPort,
		ServerArgs: []string{"--stub"},
	}
}

func TestDialLoopbackRejectsNonLoopback(t *testing.T) {
	if err := dialLoopback("8.8.8.8:80", time.Millisecond); err == nil {
		t.Fatal("非环回地址必须拒绝，且不得发拨号")
	}
	if err := dialLoopback("example.com:80", time.Millisecond); err == nil {
		t.Fatal("非环回主机必须拒绝")
	}
}

func TestDeployMissingBinaryRecordsErrorAndStartsNothing(t *testing.T) {
	ctx := context.Background()
	store := newMemStore()
	m, err := NewManager(Options{Store: store, DataDir: t.TempDir(), ChiselPath: filepath.Join(t.TempDir(), "no-such-chisel")})
	if err != nil {
		t.Fatal(err)
	}
	if m.ChiselPath() != "" {
		t.Fatalf("不可读路径应被清空, got %q", m.ChiselPath())
	}
	rec, err := m.Deploy(ctx, socksPlan(11, 20801, 20001))
	if err == nil {
		t.Fatal("缺失二进制应返回错误")
	}
	if rec == nil || rec.State != db.TunnelError {
		t.Fatalf("台账应为 error: %+v", rec)
	}
	var p Plan
	_ = json.Unmarshal(rec.DeployParams, &p)
	if rec.RemotePID != 0 && processAlive(rec.RemotePID) {
		t.Fatalf("不应拉起进程 remote_pid=%d", rec.RemotePID)
	}
	if p.ServerPID != 0 && processAlive(p.ServerPID) {
		t.Fatalf("deploy_params 中不应有活进程 pid=%d", p.ServerPID)
	}
}

func TestDeployStubAliveAndPickUpstream(t *testing.T) {
	ctx := context.Background()
	stub := buildStub(t)
	store := newMemStore()
	m, err := NewManager(Options{Store: store, DataDir: t.TempDir(), ChiselPath: stub})
	if err != nil {
		t.Fatal(err)
	}
	socks, listen := freeListenPort(t), freeListenPort(t)
	plan := socksPlan(21, socks, listen)
	rec, err := m.Deploy(ctx, plan)
	if err != nil {
		t.Fatalf("Deploy stub: %v rec=%+v", err, rec)
	}
	t.Cleanup(func() { _ = m.Teardown(context.Background(), rec.ID) })
	if rec.State != db.TunnelAlive {
		t.Fatalf("stub 成功应变 alive, got %+v", rec)
	}
	var p Plan
	if err := json.Unmarshal(rec.DeployParams, &p); err != nil || p.ServerPID <= 0 {
		t.Fatalf("应回写 pid: %v %+v", err, p)
	}
	if !processAlive(p.ServerPID) {
		t.Fatalf("stub 进程应仍在 pid=%d", p.ServerPID)
	}
	if p.SocksPort != socks || rec.ListenPort != listen {
		t.Fatalf("应持久化端口 socks=%d listen=%d rec.listen=%d", socks, listen, rec.ListenPort)
	}
	want := "socks5://" + net.JoinHostPort("127.0.0.1", itoa(socks))
	if got := pickUpstreamFor([]*db.TunnelRecord{rec}, "http://127.0.0.1:9"); got != want {
		t.Fatalf("pickUpstream = %q, want %q", got, want)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestTeardownKillsProcess(t *testing.T) {
	ctx := context.Background()
	stub := buildStub(t)
	m, err := NewManager(Options{Store: newMemStore(), DataDir: t.TempDir(), ChiselPath: stub})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := m.Deploy(ctx, socksPlan(31, freeListenPort(t), freeListenPort(t)))
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	var p Plan
	_ = json.Unmarshal(rec.DeployParams, &p)
	if !processAlive(p.ServerPID) {
		t.Fatal("部署后进程应存活")
	}
	if err := m.Teardown(ctx, rec.ID); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	// 给进程一点退出时间
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && processAlive(p.ServerPID) {
		time.Sleep(20 * time.Millisecond)
	}
	if processAlive(p.ServerPID) {
		t.Fatalf("teardown 后 pid %d 仍在", p.ServerPID)
	}
	got, _ := m.store.Get(ctx, rec.ID)
	if got == nil || got.State != db.TunnelStopped {
		t.Fatalf("台账应为 stopped: %+v", got)
	}
	// 幂等
	if err := m.Teardown(ctx, rec.ID); err != nil {
		t.Fatalf("幂等 Teardown: %v", err)
	}
}

func TestTwoTaskDeploysDoNotStompUpstream(t *testing.T) {
	ctx := context.Background()
	stub := buildStub(t)
	store := newMemStore()
	m, err := NewManager(Options{Store: store, DataDir: t.TempDir(), ChiselPath: stub})
	if err != nil {
		t.Fatal(err)
	}
	a, err := m.Deploy(ctx, socksPlan(41, freeListenPort(t), freeListenPort(t)))
	if err != nil {
		t.Fatalf("deploy A: %v", err)
	}
	b, err := m.Deploy(ctx, socksPlan(42, freeListenPort(t), freeListenPort(t)))
	if err != nil {
		t.Fatalf("deploy B: %v", err)
	}
	t.Cleanup(func() {
		_ = m.Teardown(context.Background(), a.ID)
		_ = m.Teardown(context.Background(), b.ID)
	})
	recsA, _ := store.ListByTask(ctx, 41)
	recsB, _ := store.ListByTask(ctx, 42)
	upA := pickUpstreamFor(recsA, "http://global")
	upB := pickUpstreamFor(recsB, "http://global")
	if upA == upB || upA == "http://global" || upB == "http://global" {
		t.Fatalf("两任务上游应各自独立: %q / %q", upA, upB)
	}
	var pa, pb Plan
	_ = json.Unmarshal(a.DeployParams, &pa)
	_ = json.Unmarshal(b.DeployParams, &pb)
	if pa.ServerPID == pb.ServerPID {
		t.Fatal("两任务不应共享同一 pid")
	}
	// 回收 A 不得打死 B
	if err := m.Teardown(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && processAlive(pa.ServerPID) {
		time.Sleep(20 * time.Millisecond)
	}
	if processAlive(pa.ServerPID) {
		t.Fatal("任务 A 进程应被回收")
	}
	if !processAlive(pb.ServerPID) {
		t.Fatal("任务 B 进程被踩踏")
	}
	recsB, _ = store.ListByTask(ctx, 42)
	if got := pickUpstreamFor(recsB, "http://global"); got != upB {
		t.Fatalf("任务 B 上游被踩踏: %q → %q", upB, got)
	}
}

func TestReconcileOrphansMarksDeadPidError(t *testing.T) {
	ctx := context.Background()
	store := newMemStore()
	m, err := NewManager(Options{Store: store, DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(Plan{Kind: KindSocks, SocksPort: 20801, ServerPID: 1_000_000_007})
	id, err := store.Create(ctx, &db.TunnelRecord{TaskID: 51, Kind: KindSocks, State: db.TunnelAlive, DeployParams: raw})
	if err != nil {
		t.Fatal(err)
	}
	m.ReconcileOrphans(ctx)
	rec, _ := store.Get(ctx, id)
	if rec == nil || rec.State != db.TunnelError {
		t.Fatalf("死 pid 不得继续装活: %+v", rec)
	}
}

func TestReconcileOrphansKeepsLiveLoopback(t *testing.T) {
	ctx := context.Background()
	stub := buildStub(t)
	store := newMemStore()
	m, err := NewManager(Options{Store: store, DataDir: t.TempDir(), ChiselPath: stub})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := m.Deploy(ctx, socksPlan(52, freeListenPort(t), freeListenPort(t)))
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	t.Cleanup(func() { _ = m.Teardown(context.Background(), rec.ID) })
	// 模拟进程重启：丢掉内存句柄后再对账。
	m2, err := NewManager(Options{Store: store, DataDir: t.TempDir(), ChiselPath: stub})
	if err != nil {
		t.Fatal(err)
	}
	m2.ReconcileOrphans(ctx)
	got, _ := store.Get(ctx, rec.ID)
	if got == nil || got.State != db.TunnelAlive {
		t.Fatalf("活进程且环回入口可连应保持 alive: %+v", got)
	}
	if err := m2.Teardown(ctx, rec.ID); err != nil {
		t.Fatalf("对账后仍应能 teardown: %v", err)
	}
}

// pickUpstreamFor 复用与 server 层相同的选择规则，避免测试依赖 server 包。
func pickUpstreamFor(recs []*db.TunnelRecord, globalProxy string) string {
	bestID := int64(-1)
	socksPort := 0
	var user, pass string
	for _, r := range recs {
		if r.State != db.TunnelAlive || r.Kind != KindSocks || r.ID <= bestID {
			continue
		}
		var p Plan
		if json.Unmarshal(r.DeployParams, &p) != nil || p.SocksPort <= 0 {
			continue
		}
		bestID, socksPort = r.ID, p.SocksPort
		user, pass = "", ""
		if r.Adapter == AdapterSuo5 {
			user, pass = p.AuthUser, p.AuthPass
		}
	}
	if socksPort > 0 {
		addr := net.JoinHostPort("127.0.0.1", itoa(socksPort))
		if user != "" {
			return "socks5://" + user + ":" + pass + "@" + addr
		}
		return "socks5://" + addr
	}
	return globalProxy
}

func parsePlan(t *testing.T, rec *db.TunnelRecord) Plan {
	t.Helper()
	var p Plan
	if rec == nil {
		t.Fatal("nil record")
	}
	if err := json.Unmarshal(rec.DeployParams, &p); err != nil {
		t.Fatalf("plan: %v", err)
	}
	return p
}

func TestReconnectInfoIncludesAUTHFields(t *testing.T) {
	p := Plan{
		Kind: KindSocks, AuthUser: "artex", AuthPass: "fixture-pass",
		ListenPort: 20001, SocksPort: 20801,
		ClientArgs: []string{"client", "http://127.0.0.1:20001", "R:127.0.0.1:20801:socks"},
	}
	info := ReconnectInfo(&p)
	if info["auth_user"] != "artex" || info["auth_pass"] != "fixture-pass" {
		t.Fatalf("worker 结果必须含 auth_user/auth_pass: %#v", info)
	}
	if info["AUTH"] != "artex:fixture-pass" {
		t.Fatalf("worker 结果必须含可写入 AUTH 环境变量的值, got %#v", info["AUTH"])
	}
	if _, ok := info["client_args"]; !ok {
		t.Fatal("应含 client_args")
	}
}

func TestPublicTunnelRecordOmitsPassword(t *testing.T) {
	p := Plan{Kind: KindSocks, AuthUser: "artex", AuthPass: "fixture-pass", StatusNote: WaitingEntryNote, SocksPort: 20801}
	raw, _ := json.Marshal(p)
	rec := &db.TunnelRecord{ID: 7, Kind: KindSocks, State: db.TunnelDeploying, Error: "", DeployParams: raw}
	item := PublicTunnelRecord(rec)
	b, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "fixture-pass") || strings.Contains(s, "auth_pass") || strings.Contains(s, "deploy_params") {
		t.Fatalf("列表不得含口令或完整 deploy_params: %s", s)
	}
	if item["error"] != nil {
		t.Fatalf("deploying 提示不得占用 error: %#v", item["error"])
	}
	if item["status"] != WaitingEntryNote && item["note"] != WaitingEntryNote {
		t.Fatalf("等待说明应在 note/status: %#v", item)
	}
}

func TestDeployListenOnlyStaysDeployingUntilEntryReady(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SIGUSR1 仅 Unix 支持，defer-entry 时序无法在 Windows 模拟")
	}
	ctx := context.Background()
	store := newMemStore()
	m, err := NewManager(Options{Store: store, DataDir: t.TempDir(), ChiselPath: buildStub(t)})
	if err != nil {
		t.Fatal(err)
	}
	m.Starter = deferEntryStarter
	socks, listen := freeListenPort(t), freeListenPort(t)
	plan := socksPlan(61, socks, listen)
	plan.AuthUser, plan.AuthPass = "artex", "fixture-pass"
	rec, err := m.Deploy(ctx, plan)
	if err != nil {
		t.Fatalf("Deploy: %v rec=%+v", err, rec)
	}
	t.Cleanup(func() { _ = m.Teardown(context.Background(), rec.ID) })
	if rec.State != db.TunnelDeploying {
		t.Fatalf("只听 ListenPort 时应保持 deploying, got %+v", rec)
	}
	if rec.Error != "" {
		t.Fatalf("等待入口的说明不得写入 error 列: %q", rec.Error)
	}
	p := parsePlan(t, rec)
	if p.StatusNote != WaitingEntryNote {
		t.Fatalf("等待说明应在 status_note: %q", p.StatusNote)
	}
	info := ReconnectInfo(&p)
	if info["auth_user"] != "artex" || info["auth_pass"] != "fixture-pass" || info["AUTH"] != "artex:fixture-pass" {
		t.Fatalf("Deploy 后 reconnect 必须含 AUTH 字段: %#v", info)
	}
	listed, err := json.Marshal(PublicTunnelRecord(rec))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(listed), "fixture-pass") {
		t.Fatalf("列表不得回显口令: %s", listed)
	}
	if p.ServerPID <= 0 || !processAlive(p.ServerPID) {
		t.Fatal("不得在消费入口未就绪时回滚杀掉 server")
	}
	if !listenReady(&p) {
		t.Fatal("ListenPort 应已可连")
	}
	if entryReady(&p) {
		t.Fatal("此时 SocksPort 不应可连")
	}
	if got := pickUpstreamFor([]*db.TunnelRecord{rec}, "http://global"); got != "http://global" {
		t.Fatalf("socks 未就绪时不得被 pickUpstream 选中: %q", got)
	}

	time.Sleep(2200 * time.Millisecond)
	if !processAlive(p.ServerPID) {
		t.Fatal("超时后仍不得回滚杀掉只听 ListenPort 的 server")
	}
	still, _ := store.Get(ctx, rec.ID)
	if still == nil || still.State != db.TunnelDeploying {
		t.Fatalf("超时后应仍为 deploying: %+v", still)
	}

	held, err := m.PromoteIfEntryReady(ctx, rec.ID)
	if err != nil {
		t.Fatalf("入口未就绪时 Promote 不应报错: %v", err)
	}
	if held == nil || held.State != db.TunnelDeploying {
		t.Fatalf("入口未就绪不得晋升: %+v", held)
	}

	if err := signalUSR1(p.ServerPID); err != nil {
		t.Fatalf("SIGUSR1: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !entryReady(&p) {
		time.Sleep(20 * time.Millisecond)
	}
	if !entryReady(&p) {
		t.Fatal("SIGUSR1 后 SocksPort 应可连")
	}
	pending, _ := store.Get(ctx, rec.ID)
	if got := pickUpstreamFor([]*db.TunnelRecord{pending}, "http://global"); got != "http://global" {
		t.Fatalf("未晋升前即入口已起也不得被选中: %q", got)
	}

	got, err := m.PromoteIfEntryReady(ctx, rec.ID)
	if err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if got == nil || got.State != db.TunnelAlive {
		t.Fatalf("入口就绪后应晋升 alive: %+v", got)
	}
	want := "socks5://" + net.JoinHostPort("127.0.0.1", itoa(socks))
	if up := pickUpstreamFor([]*db.TunnelRecord{got}, "http://global"); up != want {
		t.Fatalf("晋升后 pickUpstream=%q, want %q", up, want)
	}
}

func TestReconcileOrphansDoesNotKillListenOnlyServer(t *testing.T) {
	ctx := context.Background()
	store := newMemStore()
	m, err := NewManager(Options{Store: store, DataDir: t.TempDir(), ChiselPath: buildStub(t)})
	if err != nil {
		t.Fatal(err)
	}
	m.Starter = deferEntryStarter
	rec, err := m.Deploy(ctx, socksPlan(62, freeListenPort(t), freeListenPort(t)))
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	t.Cleanup(func() { _ = m.Teardown(context.Background(), rec.ID) })
	p := parsePlan(t, rec)
	// 伪装成误标 alive，对账必须降为 deploying 且不得杀进程。
	if err := store.UpdateState(ctx, rec.ID, db.TunnelAlive, ""); err != nil {
		t.Fatal(err)
	}
	m2, err := NewManager(Options{Store: store, DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	m2.ReconcileOrphans(ctx)
	got, _ := store.Get(ctx, rec.ID)
	if got == nil || got.State != db.TunnelDeploying {
		t.Fatalf("只听 ListenPort 的活 server 不得继续装活，也不得标成无进程的 error: %+v", got)
	}
	if got.Error != "" {
		t.Fatalf("对账降级说明不得占用 error 列: %q", got.Error)
	}
	gp := parsePlan(t, got)
	if gp.StatusNote == "" {
		t.Fatal("对账降级说明应在 status_note")
	}
	if !processAlive(p.ServerPID) {
		t.Fatal("对账不得杀掉只听 ListenPort 的活 server")
	}
	listed, _ := json.Marshal(PublicTunnelRecord(got))
	if strings.Contains(string(listed), "fixture-pass") {
		t.Fatalf("列表不得回显口令: %s", listed)
	}
}

func TestDeployRejectsSuo5WithoutUsingChiselArgs(t *testing.T) {
	ctx := context.Background()
	m, err := NewManager(Options{Store: newMemStore(), DataDir: t.TempDir(), ChiselPath: buildStub(t), Suo5Path: buildStub(t)})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := m.Deploy(ctx, &Plan{
		Kind: KindSocks, Adapter: AdapterSuo5, TaskID: 63,
		ListenPort: 20001, SocksPort: 20801,
		ServerArgs: []string{"server", "--host", "0.0.0.0", "-p", "20001", "--reverse", "--authfile", "x"},
	})
	if err == nil {
		t.Fatal("suo5 应被明确拒绝")
	}
	if rec == nil || rec.State != db.TunnelError {
		t.Fatalf("应记录 error 台账: %+v", rec)
	}
	if rec.RemotePID != 0 {
		t.Fatalf("不得拉起进程: %+v", rec)
	}
	var p Plan
	_ = json.Unmarshal(rec.DeployParams, &p)
	if p.ServerPID != 0 && processAlive(p.ServerPID) {
		t.Fatalf("不得 exec suo5/chisel 参数: pid=%d", p.ServerPID)
	}
}
