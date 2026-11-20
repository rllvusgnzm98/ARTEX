// taskproxy.go：worker 流量按任务绑定上游——每任务懒建独立 traffic.Traffic
// (MITM)实例，上游 = 该任务当前最高 id 的 alive socks 隧道入口；无隧道回落
// 全局出口代理（globalProxy）或直连。保留既有 traffic 包，不使用进程级
// SetUpstream，避免任务之间互相踩踏上游。
//
// 实例目录 data/traffic-tasks/<taskID>/（独立 CA）；SetUpstreamProxy 是实例
// 字段、原子热切换。实例生命周期与任务绑定，进程退出 Close 全清。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/artex/traffic"
	"github.com/Autumn-27/artex/tunnel"
)

// dynManagedPorts 是本刀本地的受管端口登记（不引入独立端口审计包）。
var dynManagedPorts sync.Map

func registerManagedPort(port int) { dynManagedPorts.Store(port, true) }

func unregisterManagedPort(port int) { dynManagedPorts.Delete(port) }

// tunnelLister 是任务隧道台账的最小读接口（*db.TunnelStore 满足；测试可注入假实现）。
type tunnelLister interface {
	ListByTask(ctx context.Context, taskID int64) ([]*db.TunnelRecord, error)
}

// taskProxyInst 是一个任务级 MITM 实例及其受管端口/当前上游。
type taskProxyInst struct {
	tr       *traffic.Traffic
	port     int
	upstream string
}

// roeGateTTL 是任务代理范围/模式缓存的有效期。add_task_scope 成功后主动失效。
const roeGateTTL = 5 * time.Second

// roeGateDeps 是任务代理 host gate 的读取与告警依赖。测试可注入。
type roeGateDeps struct {
	mode  func() string
	scope func(taskID int64) ([]guard.ScopeRule, error)
	warn  func(taskID int64, host, msg string)
}

type roeSnap struct {
	mode  string
	rules []guard.ScopeRule
	err   error
	at    time.Time
}

// roeGateCache 按 taskID 缓存 enforcement mode 与官方范围，避免每个请求打库。
type roeGateCache struct {
	ttl   time.Duration
	now   func() time.Time
	deps  roeGateDeps
	mu    sync.Mutex
	snaps map[int64]roeSnap
}

func (c *roeGateCache) clock() time.Time {
	if c != nil && c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *roeGateCache) get(taskID int64) (string, []guard.ScopeRule, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock()
	if s, ok := c.snaps[taskID]; ok && now.Sub(s.at) < c.ttl {
		return s.mode, s.rules, s.err
	}
	mode := "warn"
	if c.deps.mode != nil {
		mode = normalizeRoEMode(c.deps.mode())
	}
	var (
		rules []guard.ScopeRule
		err   error
	)
	if mode != "off" {
		if c.deps.scope == nil {
			err = fmt.Errorf("范围存储未就绪")
		} else {
			rules, err = c.deps.scope(taskID)
		}
	}
	c.snaps[taskID] = roeSnap{mode: mode, rules: rules, err: err, at: now}
	return mode, rules, err
}

func (c *roeGateCache) invalidate(taskID int64) {
	if c == nil {
		return
	}
	c.mu.Lock()
	delete(c.snaps, taskID)
	c.mu.Unlock()
}

// taskProxyManager 按 taskID 懒建并管理任务级 MITM 实例。零值不可用。
type taskProxyManager struct {
	dir         string
	store       tunnelLister
	globalProxy func() string
	portMin     int
	portMax     int
	mu          sync.Mutex
	proxies     map[int64]*taskProxyInst
	roe         *roeGateCache
}

func newTaskProxyManager(dir string, store tunnelLister, globalProxy func() string, portMin, portMax int) *taskProxyManager {
	return &taskProxyManager{
		dir: filepath.Join(dir, "traffic-tasks"), store: store, globalProxy: globalProxy,
		portMin: portMin, portMax: portMax, proxies: map[int64]*taskProxyInst{},
	}
}

// pickUpstream 选任务上游：最新（id 最大）的 alive socks 隧道入口；无可用隧道
// 回落全局出口代理（可为 "" = 直连）。portfwd 不是上游形态，跳过。
// suo5 入口若带鉴权，上游 URL 从台账 deploy_params 内嵌 user:pass。纯函数。
func pickUpstream(recs []*db.TunnelRecord, globalProxy string) string {
	bestID := int64(-1)
	socksPort := 0
	var user, pass string
	for _, r := range recs {
		if r.State != db.TunnelAlive || r.Kind != tunnel.KindSocks || r.ID <= bestID {
			continue
		}
		var p tunnel.Plan
		if json.Unmarshal(r.DeployParams, &p) != nil || p.SocksPort <= 0 {
			continue
		}
		bestID, socksPort = r.ID, p.SocksPort
		user, pass = "", ""
		if r.Adapter == tunnel.AdapterSuo5 {
			user, pass = p.AuthUser, p.AuthPass
		}
	}
	if socksPort > 0 {
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort))
		if user != "" {
			return "socks5://" + user + ":" + pass + "@" + addr
		}
		return "socks5://" + addr
	}
	return globalProxy
}

func (m *taskProxyManager) resolveUpstream(ctx context.Context, taskID int64) (string, error) {
	recs, err := m.store.ListByTask(ctx, taskID)
	if err != nil {
		return "", err
	}
	gp := ""
	if m.globalProxy != nil {
		gp = m.globalProxy()
	}
	return pickUpstream(recs, gp), nil
}

// ForTask 返回任务 worker 应使用的代理地址与 CA：首次调用懒建该任务的 MITM
// 实例，之后每次调用顺手重算上游。建实例失败只记日志并返回 "","",
// 调用方回落全局代理。
func (m *taskProxyManager) ForTask(ctx context.Context, taskID int64) (addr, caCert string) {
	if taskID <= 0 {
		return "", ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	inst := m.proxies[taskID]
	if inst == nil {
		created, err := m.buildLocked(ctx, taskID)
		if err != nil {
			log.Printf("[taskproxy] 任务 %d MITM 实例创建失败(回落全局代理): %v", taskID, err)
			return "", ""
		}
		inst = created
		m.proxies[taskID] = inst
		log.Printf("[taskproxy] 任务 %d MITM 实例就绪 %s(CA %s)", taskID, inst.tr.ProxyAddr(), inst.tr.CACertPath())
	}
	m.refreshLocked(ctx, taskID, inst)
	return inst.tr.ProxyAddr(), inst.tr.CACertPath()
}

func (m *taskProxyManager) buildLocked(ctx context.Context, taskID int64) (*taskProxyInst, error) {
	used := map[int]bool{}
	for _, inst := range m.proxies {
		used[inst.port] = true
	}
	port, err := tunnel.AllocatePort(m.portMin, m.portMax, used, tunnel.CanListen)
	if err != nil {
		return nil, err
	}
	tr, err := traffic.Open(filepath.Join(m.dir, strconv.FormatInt(taskID, 10)),
		net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	inst := &taskProxyInst{tr: tr, port: port}
	if up, err := m.resolveUpstream(ctx, taskID); err != nil {
		log.Printf("[taskproxy] 任务 %d 台账读取失败,初始上游按回落处理: %v", taskID, err)
		gp := ""
		if m.globalProxy != nil {
			gp = m.globalProxy()
		}
		inst.upstream = gp
	} else {
		inst.upstream = up
	}
	if err := tr.SetUpstreamProxy(inst.upstream); err != nil {
		_ = tr.Close()
		return nil, err
	}
	if gate := m.hostGate(taskID); gate != nil {
		tr.SetHostGate(gate)
	}
	go func() {
		if err := tr.Start(); err != nil {
			log.Printf("[taskproxy] 任务 %d MITM 监听结束: %v", taskID, err)
		}
	}()
	registerManagedPort(port)
	return inst, nil
}

func (m *taskProxyManager) refreshLocked(ctx context.Context, taskID int64, inst *taskProxyInst) {
	up, err := m.resolveUpstream(ctx, taskID)
	if err != nil {
		log.Printf("[taskproxy] 任务 %d 台账读取失败,上游保持 %q: %v", taskID, inst.upstream, err)
		return
	}
	if up == inst.upstream {
		return
	}
	if err := inst.tr.SetUpstreamProxy(up); err != nil {
		log.Printf("[taskproxy] 任务 %d 上游 %q 无效,保持 %q: %v", taskID, up, inst.upstream, err)
		return
	}
	log.Printf("[taskproxy] 任务 %d 上游热切换: %q → %q", taskID, inst.upstream, up)
	inst.upstream = up
}

// Refresh 在隧道状态变化时热切换该任务实例上游。实例不存在时不建（懒建语义）。
func (m *taskProxyManager) Refresh(ctx context.Context, taskID int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if inst := m.proxies[taskID]; inst != nil {
		m.refreshLocked(ctx, taskID, inst)
	}
}

// RefreshAll 重算全部实例上游（全局出口代理变更时，无隧道任务的回落上游随之变）。
func (m *taskProxyManager) RefreshAll(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, inst := range m.proxies {
		m.refreshLocked(ctx, id, inst)
	}
}

// CloseTask 销毁任务实例：停监听、关索引、端口注销；CA 目录保留。幂等。
func (m *taskProxyManager) CloseTask(taskID int64) {
	m.mu.Lock()
	inst := m.proxies[taskID]
	delete(m.proxies, taskID)
	m.mu.Unlock()
	if inst == nil {
		return
	}
	unregisterManagedPort(inst.port)
	if err := inst.tr.Close(); err != nil {
		log.Printf("[taskproxy] 任务 %d MITM 实例关闭: %v", taskID, err)
	}
}

// useRoE 安装任务代理的 host gate 数据源。未调用时实例不挂 gate，转发行为不变。
func (m *taskProxyManager) useRoE(deps roeGateDeps) {
	if m == nil {
		return
	}
	m.roe = &roeGateCache{ttl: roeGateTTL, deps: deps, snaps: map[int64]roeSnap{}}
}

// invalidateRoE 丢掉一个任务的范围缓存。add_task_scope 成功后调用，使新范围立即生效。
func (m *taskProxyManager) invalidateRoE(taskID int64) {
	if m == nil || m.roe == nil {
		return
	}
	m.roe.invalidate(taskID)
}

// hostGate 是该任务 MITM 的目标检查。nil 表示未启用。
// strict 越界或范围读失败拒绝；warn 放行并记 activity/log；off 放行。
func (m *taskProxyManager) hostGate(taskID int64) func(string) error {
	if m == nil || m.roe == nil || taskID <= 0 {
		return nil
	}
	return func(host string) error {
		host = strings.TrimSpace(host)
		if host == "" {
			return nil
		}
		mode, rules, err := m.roe.get(taskID)
		if mode == "off" {
			return nil
		}
		if err != nil {
			log.Printf("[taskproxy][roe] task %d 范围读取失败(mode=%s)", taskID, mode)
			if mode == "strict" {
				return fmt.Errorf("RoE 授权范围检查：主机 %s 的任务 %d 范围读取失败，strict 拒绝放行。可把目标加入任务范围，或调整 roe_enforcement 为 warn/off 回退。", host, taskID)
			}
			m.noteRoEWarn(taskID, host, fmt.Sprintf("⚠ RoE 授权范围检查：主机 %s 的任务 %d 范围读取失败，warn 下放行。", host, taskID))
			return nil
		}
		if guard.NewScopeMatcher(rules).Check(host) != guard.ScopeOut {
			return nil
		}
		msg := fmt.Sprintf("RoE 授权范围检查：主机 %s 不在任务 %d 已登记范围内。如需放行：把目标加入任务范围(add_task_scope)，或调整 roe_enforcement 为 warn/off。", host, taskID)
		if mode == "strict" {
			return fmt.Errorf("%s", msg)
		}
		m.noteRoEWarn(taskID, host, "⚠ "+msg)
		return nil
	}
}

func (m *taskProxyManager) noteRoEWarn(taskID int64, host, msg string) {
	if m != nil && m.roe != nil && m.roe.deps.warn != nil {
		m.roe.deps.warn(taskID, host, msg)
		return
	}
	log.Printf("[taskproxy][roe] task %d host %s: %s", taskID, host, msg)
}

// Close 进程退出时全清（幂等）。
func (m *taskProxyManager) Close() {
	m.mu.Lock()
	insts := m.proxies
	m.proxies = map[int64]*taskProxyInst{}
	m.mu.Unlock()
	for id, inst := range insts {
		unregisterManagedPort(inst.port)
		if err := inst.tr.Close(); err != nil {
			log.Printf("[taskproxy] 任务 %d MITM 实例关闭: %v", id, err)
		}
	}
}
