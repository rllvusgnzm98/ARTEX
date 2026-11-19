// manager.go 进程内适配器拉起：在平台侧 exec 已解析的 chisel/suo5（或测试 stub）
// 二进制，只对 127.0.0.1/::1 入口做健康检查，成功则台账标 alive 并回写 pid/端口。
// 二进制缺失时明确失败、state=error、不拉起进程。失败按计划层回滚，不留孤儿。
// 不对非环回地址建连，不向真实目标打洞，不投递或不在目标侧拉起 client。
package tunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
)

const (
	serverUpWait   = 2 * time.Second
	dialProbeEvery = 50 * time.Millisecond
	entryDialWait  = 2 * time.Second
)

// Store 是 Manager 需要的台账最小接口（*db.TunnelStore 满足；测试可注入内存实现）。
type Store interface {
	Create(ctx context.Context, rec *db.TunnelRecord) (int64, error)
	Get(ctx context.Context, id int64) (*db.TunnelRecord, error)
	UpdateState(ctx context.Context, id int64, state, errMsg string) error
	UpdateDeployParams(ctx context.Context, id int64, remotePID int, params json.RawMessage) error
	Delete(ctx context.Context, id int64) error
	ListByTask(ctx context.Context, taskID int64) ([]*db.TunnelRecord, error)
	ListAlive(ctx context.Context) ([]*db.TunnelRecord, error)
	ListActive(ctx context.Context) ([]*db.TunnelRecord, error)
	List(ctx context.Context) ([]*db.TunnelRecord, error)
}

// Manager 是隧道子系统的进程内运行时：本地拉起/环回探活/回滚/回收/重启对账。
type Manager struct {
	store      Store
	chiselPath string
	suo5Path   string
	dataDir    string

	OnListenStart func(port int)
	OnListenStop  func(port int)
	OnStateChange func(taskID int64)

	// Starter 可注入（测试用）。nil 时走默认 exec。
	Starter func(ctx context.Context, bin string, p *Plan) (*exec.Cmd, error)

	mu    sync.Mutex
	procs map[int64]*exec.Cmd
}

// Options 是 Manager 装配输入。ChiselPath/Suo5Path 空或不可读时，对应适配器
// Deploy 报明确错误；不把它们写成默认必装项。
type Options struct {
	Store      Store
	ChiselPath string
	Suo5Path   string
	DataDir    string
}

// ResolveChiselPath：环境变量 ARTEX_CHISEL_PATH 优先，否则 data/tools/chisel。
func ResolveChiselPath(dataDir string) string {
	if v := strings.TrimSpace(os.Getenv("ARTEX_CHISEL_PATH")); v != "" {
		return v
	}
	if strings.TrimSpace(dataDir) == "" {
		return ""
	}
	return filepath.Join(dataDir, "tools", "chisel")
}

// ResolveSuo5Path：环境变量 ARTEX_SUO5_PATH 优先，否则 data/tools/suo5。
func ResolveSuo5Path(dataDir string) string {
	if v := strings.TrimSpace(os.Getenv("ARTEX_SUO5_PATH")); v != "" {
		return v
	}
	if strings.TrimSpace(dataDir) == "" {
		return ""
	}
	return filepath.Join(dataDir, "tools", "suo5")
}

func readableFile(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// NewManager 构造运行时。二进制不可读时清空对应路径，Deploy 再报明确错误。
func NewManager(o Options) (*Manager, error) {
	if o.Store == nil {
		return nil, fmt.Errorf("tunnel.Manager 需要 store")
	}
	dir := o.DataDir
	if dir != "" {
		dir = filepath.Join(dir, "tunnels")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	m := &Manager{
		store: o.Store, dataDir: dir,
		chiselPath: o.ChiselPath, suo5Path: o.Suo5Path,
		procs: map[int64]*exec.Cmd{},
	}
	if m.chiselPath != "" && !readableFile(m.chiselPath) {
		log.Printf("[tunnel] chisel 路径不可读（%s）—— Deploy 将报明确错误（按需，非默认必装）", m.chiselPath)
		m.chiselPath = ""
	}
	if m.suo5Path != "" && !readableFile(m.suo5Path) {
		log.Printf("[tunnel] suo5 路径不可读（%s）—— adapter=suo5 的 Deploy 将报明确错误（按需，非默认必装）", m.suo5Path)
		m.suo5Path = ""
	}
	return m, nil
}

func (m *Manager) ChiselPath() string  { return m.chiselPath }
func (m *Manager) Suo5Path() string    { return m.suo5Path }
func (m *Manager) PlanDataDir() string { return m.dataDir }

func (m *Manager) notifyState(taskID int64) {
	if m.OnStateChange != nil && taskID > 0 {
		m.OnStateChange(taskID)
	}
}

func (m *Manager) saveParams(ctx context.Context, id int64, p *Plan) {
	raw, err := json.Marshal(p)
	if err != nil {
		return
	}
	if err := m.store.UpdateDeployParams(ctx, id, p.RemotePID, raw); err != nil {
		log.Printf("[tunnel] 台账参数回写失败(id=%d): %v", id, err)
	}
}

func (m *Manager) adapterBin(p *Plan) (string, error) {
	switch p.Adapter {
	case "", AdapterChisel:
		if m.chiselPath == "" {
			return "", fmt.Errorf("chisel 二进制缺失：可把二进制放到 data/tools/chisel 或设 ARTEX_CHISEL_PATH 后重试（按需，非默认必装）")
		}
		return m.chiselPath, nil
	case AdapterSuo5:
		if m.suo5Path == "" {
			return "", fmt.Errorf("suo5 二进制缺失：可设 ARTEX_SUO5_PATH 后重试（按需，非默认必装）")
		}
		return m.suo5Path, nil
	default:
		return "", fmt.Errorf("未知适配器 %q", p.Adapter)
	}
}

// Deploy 建台账行 → 进程内拉起平台侧适配器 → 只对环回入口探活 → 标 alive。
// 任一失败按计划回滚（杀本进程拉起的进程、删 authfile），台账标 error，不留孤儿。
func (m *Manager) Deploy(ctx context.Context, p *Plan) (*db.TunnelRecord, error) {
	if p == nil {
		return nil, fmt.Errorf("计划为空")
	}
	if p.Adapter == "" {
		p.Adapter = AdapterChisel
	}
	if p.Kind == KindSocks && p.SocksPort <= 0 || p.Kind == KindPortfwd && p.LocalPort <= 0 {
		return nil, fmt.Errorf("计划缺收入口端口（socks_port/local_port)")
	}
	bin, binErr := m.adapterBin(p)
	rec := &db.TunnelRecord{
		TaskID: p.TaskID, Kind: p.Kind, Adapter: p.Adapter,
		ListenHost: p.ListenHost, ListenPort: p.ListenPort,
		TargetHost: p.TargetHost, TargetPort: p.TargetPort,
		ViaSessionID: p.ViaSessionID, State: db.TunnelDeploying,
	}
	raw, _ := json.Marshal(p)
	rec.DeployParams = raw
	if binErr != nil {
		rec.State = db.TunnelError
		rec.Error = binErr.Error()
		id, err := m.store.Create(ctx, rec)
		if err != nil {
			return nil, fmt.Errorf("台账落库失败: %w", err)
		}
		m.notifyState(p.TaskID)
		rec, _ = m.store.Get(ctx, id)
		if rec == nil {
			rec = &db.TunnelRecord{ID: id, State: db.TunnelError, Error: binErr.Error(), TaskID: p.TaskID}
		}
		return rec, binErr
	}
	id, err := m.store.Create(ctx, rec)
	if err != nil {
		return nil, fmt.Errorf("台账落库失败: %w", err)
	}
	if err := m.deployLocal(ctx, id, bin, p); err != nil {
		m.rollback(ctx, id, p, err.Error())
		rec, _ = m.store.Get(ctx, id)
		if rec == nil {
			rec = &db.TunnelRecord{ID: id, State: db.TunnelError, Error: err.Error(), TaskID: p.TaskID}
		}
		return rec, err
	}
	if err := m.store.UpdateState(ctx, id, db.TunnelAlive, ""); err != nil {
		log.Printf("[tunnel] 状态回写失败(id=%d): %v", id, err)
	}
	m.notifyState(p.TaskID)
	rec, _ = m.store.Get(ctx, id)
	return rec, nil
}

func (m *Manager) deployLocal(ctx context.Context, id int64, bin string, p *Plan) error {
	if p.AuthFile != "" {
		if err := os.MkdirAll(filepath.Dir(p.AuthFile), 0o700); err != nil {
			return fmt.Errorf("层 server_process: authfile 目录失败: %w", err)
		}
		if err := os.WriteFile(p.AuthFile, []byte(p.AuthfileContent()), 0o600); err != nil {
			return fmt.Errorf("层 server_process: authfile 写入失败: %w", err)
		}
	}
	start := m.Starter
	if start == nil {
		start = defaultStart
	}
	cmd, err := start(ctx, bin, p)
	if err != nil {
		return fmt.Errorf("层 server_process: 启动失败: %w", err)
	}
	if cmd.Process == nil {
		return fmt.Errorf("层 server_process: 启动后无进程")
	}
	p.ServerPID = cmd.Process.Pid
	m.mu.Lock()
	m.procs[id] = cmd
	m.mu.Unlock()
	m.saveParams(ctx, id, p)
	if m.OnListenStart != nil && p.ListenPort > 0 {
		m.OnListenStart(p.ListenPort)
	}
	go func() { _ = cmd.Wait() }()

	if err := waitLoopbackEntry(ctx, p, entryDialWait); err != nil {
		return fmt.Errorf("层 verify: %w", err)
	}
	if p.ServerPID > 0 && !processAlive(p.ServerPID) {
		return fmt.Errorf("层 server_process: 进程启动后已退出（pid %d）", p.ServerPID)
	}
	return nil
}

func defaultStart(_ context.Context, bin string, p *Plan) (*exec.Cmd, error) {
	args := p.ServerArgs
	if p.Adapter == AdapterSuo5 && len(args) == 0 {
		// 不向非环回地址传连接参数。测试 stub 只靠环境变量绑环回端口。
		args = []string{"--stub"}
	}
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(),
		"ARTEX_TUNNEL_STUB_SOCKS="+strconv.Itoa(p.SocksPort),
		"ARTEX_TUNNEL_STUB_LISTEN="+strconv.Itoa(p.ListenPort),
		"ARTEX_TUNNEL_STUB_LOCAL="+strconv.Itoa(p.LocalPort),
	)
	if p.ServerLog != "" {
		if err := os.MkdirAll(filepath.Dir(p.ServerLog), 0o700); err == nil {
			if f, err := os.OpenFile(p.ServerLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
				cmd.Stdout, cmd.Stderr = f, f
			}
		}
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

// entryAddr 平台回环上的隧道入口（socks 或 portfwd 本地口）。只返回 127.0.0.1。
func entryAddr(p *Plan) (string, error) {
	port := p.SocksPort
	if p.Kind == KindPortfwd {
		port = p.LocalPort
	}
	if port <= 0 {
		return "", fmt.Errorf("计划缺入口端口")
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), nil
}

func isLoopbackHost(host string) bool {
	h := strings.TrimSpace(host)
	if h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "0:0:0:0:0:0:0:1" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func dialLoopback(addr string, timeout time.Duration) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || !isLoopbackHost(host) {
		return fmt.Errorf("拒绝非环回探活: %s", addr)
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func waitLoopbackEntry(ctx context.Context, p *Plan, budget time.Duration) error {
	addr, err := entryAddr(p)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(budget)
	var last error
	for time.Now().Before(deadline) {
		last = dialLoopback(addr, dialProbeEvery)
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(dialProbeEvery):
		}
	}
	if last == nil {
		last = fmt.Errorf("超时")
	}
	return fmt.Errorf("环回入口 %s 在 %v 内未就绪: %w", addr, budget, last)
}

func (m *Manager) rollback(ctx context.Context, id int64, p *Plan, reason string) {
	log.Printf("[tunnel] 部署失败回滚(id=%d): %s", id, reason)
	m.killServer(id, p)
	if p.AuthFile != "" {
		_ = os.Remove(p.AuthFile)
	}
	_ = m.store.UpdateState(ctx, id, db.TunnelError, reason)
	m.notifyState(p.TaskID)
}

func (m *Manager) killServer(id int64, p *Plan) {
	m.mu.Lock()
	cmd, ok := m.procs[id]
	delete(m.procs, id)
	m.mu.Unlock()
	if ok && cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	} else if p != nil && p.ServerPID > 0 && processAlive(p.ServerPID) && serverCmdlineMatches(p) {
		if proc, err := os.FindProcess(p.ServerPID); err == nil {
			_ = proc.Kill()
		}
	}
	if m.OnListenStop != nil && p != nil && p.ListenPort > 0 {
		m.OnListenStop(p.ListenPort)
	}
}

// Teardown 杀掉本平台拉起的进程，台账标 stopped。幂等。
func (m *Manager) Teardown(ctx context.Context, id int64) error {
	rec, err := m.store.Get(ctx, id)
	if err != nil {
		return err
	}
	if rec == nil {
		return fmt.Errorf("隧道 %d 不存在", id)
	}
	if rec.State == db.TunnelStopped {
		return nil
	}
	var p Plan
	_ = json.Unmarshal(rec.DeployParams, &p)
	m.killServer(id, &p)
	if p.AuthFile != "" {
		_ = os.Remove(p.AuthFile)
	}
	err = m.store.UpdateState(ctx, id, db.TunnelStopped, "")
	m.notifyState(rec.TaskID)
	return err
}

// ReconcileOrphans 平台重启后调用：deploying/alive 行若 pid 已死，标 error，
// 绝不把死进程继续当成 alive。pid 仍在且环回入口可连则重新纳入本进程台账。
func (m *Manager) ReconcileOrphans(ctx context.Context) {
	recs, err := m.store.ListActive(ctx)
	if err != nil {
		log.Printf("[tunnel] 重启对账读台账失败: %v", err)
		return
	}
	for _, r := range recs {
		if r == nil || (r.State != db.TunnelAlive && r.State != db.TunnelDeploying) {
			continue
		}
		var p Plan
		if err := json.Unmarshal(r.DeployParams, &p); err != nil {
			_ = m.store.UpdateState(ctx, r.ID, db.TunnelError, "重启对账：deploy_params 解析失败")
			m.notifyState(r.TaskID)
			continue
		}
		if p.ServerPID <= 0 || !processAlive(p.ServerPID) {
			_ = m.store.UpdateState(ctx, r.ID, db.TunnelError, "平台重启后进程已不在，不能再当作存活上游")
			m.notifyState(r.TaskID)
			continue
		}
		if err := dialLoopbackMust(p); err != nil {
			if processAlive(p.ServerPID) && serverCmdlineMatches(&p) {
				if proc, e := os.FindProcess(p.ServerPID); e == nil {
					_ = proc.Kill()
				}
			}
			_ = m.store.UpdateState(ctx, r.ID, db.TunnelError, "平台重启后环回入口不可连: "+err.Error())
			m.notifyState(r.TaskID)
			continue
		}
		// 进程仍在且入口可连：纳入句柄，必要时把 deploying 提升为 alive。
		if proc, err := os.FindProcess(p.ServerPID); err == nil {
			m.mu.Lock()
			m.procs[r.ID] = &exec.Cmd{Process: proc}
			m.mu.Unlock()
		}
		if r.State == db.TunnelDeploying {
			_ = m.store.UpdateState(ctx, r.ID, db.TunnelAlive, "")
			m.notifyState(r.TaskID)
		}
	}
}

func dialLoopbackMust(p Plan) error {
	addr, err := entryAddr(&p)
	if err != nil {
		return err
	}
	return dialLoopback(addr, time.Second)
}

// OccupiedPorts 汇总未终结隧道占用的平台端口。
func (m *Manager) OccupiedPorts(ctx context.Context) (map[int]bool, error) {
	recs, err := m.store.ListActive(ctx)
	if err != nil {
		return nil, err
	}
	return UsedPorts(recs), nil
}

// UsedPorts 汇总给定台账行占用的 listen/socks/local 端口。
func UsedPorts(recs []*db.TunnelRecord) map[int]bool {
	used := map[int]bool{}
	for _, r := range recs {
		if r == nil {
			continue
		}
		if r.ListenPort > 0 {
			used[r.ListenPort] = true
		}
		var p Plan
		if json.Unmarshal(r.DeployParams, &p) == nil {
			if p.SocksPort > 0 {
				used[p.SocksPort] = true
			}
			if p.LocalPort > 0 {
				used[p.LocalPort] = true
			}
		}
	}
	return used
}

func (m *Manager) ActiveRecords(ctx context.Context) ([]*db.TunnelRecord, error) {
	return m.store.ListActive(ctx)
}

func (m *Manager) TaskRecords(ctx context.Context, taskID int64) ([]*db.TunnelRecord, error) {
	return m.store.ListByTask(ctx, taskID)
}
