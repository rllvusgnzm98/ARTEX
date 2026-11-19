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
	"log"
	"net"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/Autumn-27/artex/db"
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

// taskProxyManager 按 taskID 懒建并管理任务级 MITM 实例。零值不可用。
type taskProxyManager struct {
	dir         string
	store       tunnelLister
	globalProxy func() string
	portMin     int
	portMax     int
	mu          sync.Mutex
	proxies     map[int64]*taskProxyInst
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
