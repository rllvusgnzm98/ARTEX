// tunnel.go 装配隧道台账与默认工具（list / probe / deploy / teardown）。
// 进程内拉起适配器（chisel/suo5 路径按需解析）；只对环回入口探活，
// 不对真实目标打洞。外部二进制按需，非默认必装。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/tunnel"
	actool "github.com/Autumn-27/norma/tool"
)

// tunnelRuntime 是本刀的台账运行时，内嵌进程内 Manager（本地拉起/环回探活/回收）。
type tunnelRuntime struct {
	store   *db.TunnelStore
	dataDir string
	mgr     *tunnel.Manager
}

func (rt *tunnelRuntime) ListByTask(ctx context.Context, taskID int64) ([]*db.TunnelRecord, error) {
	if rt == nil || rt.store == nil {
		return nil, fmt.Errorf("隧道台账未就绪")
	}
	return rt.store.ListByTask(ctx, taskID)
}

func (rt *tunnelRuntime) List(ctx context.Context) ([]*db.TunnelRecord, error) {
	if rt == nil || rt.store == nil {
		return nil, fmt.Errorf("隧道台账未就绪")
	}
	return rt.store.List(ctx)
}

func (s *Server) initTunnels(dataDir string) {
	if s.m == nil || s.m.PG() == nil {
		return
	}
	store := db.NewTunnelStore(s.m.PG())
	mgr, err := tunnel.NewManager(tunnel.Options{
		Store:      store,
		ChiselPath: tunnel.ResolveChiselPath(dataDir),
		Suo5Path:   tunnel.ResolveSuo5Path(dataDir),
		DataDir:    dataDir,
	})
	if err != nil {
		log.Printf("[tunnel] Manager 初始化失败（台账仍可用）: %v", err)
		rt := &tunnelRuntime{store: store, dataDir: dataDir}
		s.tunnels = rt
		s.tunnelLive = rt
		return
	}
	mgr.OnListenStart = registerManagedPort
	mgr.OnListenStop = unregisterManagedPort
	mgr.OnStateChange = s.m.RefreshTaskProxy
	mgr.ReconcileOrphans(s.ctx)
	rt := &tunnelRuntime{store: store, dataDir: mgr.PlanDataDir(), mgr: mgr}
	s.tunnels = rt
	s.tunnelLive = rt
	log.Printf("[tunnel] 隧道台账已就绪（端口池 %s；适配器按需进程内拉起，仅环回探活）", config.TunnelPortRange())
}

func callbackHost() (string, error) {
	addr := config.CallbackAddr()
	if addr == "" {
		return "", fmt.Errorf("未配置平台回连地址：设 ARTEX_CALLBACK_ADDR=<目标可达的平台IP:端口> 后重试")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, nil
	}
	return host, nil
}

func (s *Server) occupiedPorts(ctx context.Context) (map[int]bool, error) {
	used := map[int]bool{}
	if s.tunnels == nil || s.tunnels.store == nil {
		return used, nil
	}
	recs, err := s.tunnels.store.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range recs {
		if r == nil || r.State == db.TunnelStopped || r.State == db.TunnelError {
			continue
		}
		if r.ListenPort > 0 {
			used[r.ListenPort] = true
		}
		var p tunnel.Plan
		if json.Unmarshal(r.DeployParams, &p) == nil {
			if p.SocksPort > 0 {
				used[p.SocksPort] = true
			}
			if p.LocalPort > 0 {
				used[p.LocalPort] = true
			}
		}
	}
	return used, nil
}

func (s *Server) teardownTunnel(ctx context.Context, id int64) error {
	if s.tunnels != nil && s.tunnels.mgr != nil {
		return s.tunnels.mgr.Teardown(ctx, id)
	}
	if s.tunnels == nil || s.tunnels.store == nil {
		return fmt.Errorf("隧道台账未就绪")
	}
	rec, err := s.tunnels.store.Get(ctx, id)
	if err != nil {
		return err
	}
	if rec == nil {
		return fmt.Errorf("隧道 %d 不存在", id)
	}
	if err := s.tunnels.store.UpdateState(ctx, id, db.TunnelStopped, ""); err != nil {
		return err
	}
	if s.m != nil {
		s.m.RefreshTaskProxy(rec.TaskID)
	}
	return nil
}

func (s *Server) tunnelTools() []actool.CoreTool {
	if s.tunnels == nil {
		return nil
	}
	return []actool.CoreTool{
		s.tunnelProbeTool(),
		s.tunnelDeployTool(),
		s.tunnelListTool(),
		s.tunnelTeardownTool(),
	}
}

func (s *Server) tunnelProbeTool() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "tunnel_probe",
		Description: "【隧道·probe】检查平台回连地址与端口池是否已配置，并确认立足点会话存在，给出适配器选型建议（chisel 或 suo5）。" +
			"本刀不向真实目标发探测包。起隧道前先跑这个。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "integer", "description": "立足点会话 id"},
			},
			"required": []any{"session_id"},
		},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				SessionID int64 `json:"session_id"`
			}
			_ = json.Unmarshal(in, &a)
			if _, err := s.lookupSession(a.SessionID); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			cb, cbErr := callbackHost()
			out := map[string]any{
				"session_id":        a.SessionID,
				"port_range":        config.TunnelPortRange(),
				"suggested_adapter": "chisel",
				"note":              "本刀不向真实目标发探测包。能 TCP 回连平台时建议 adapter=chisel；出网受限时可显式 adapter=suo5。外部二进制按需，非默认必装。",
			}
			if cbErr != nil {
				out["callback_configured"] = false
				out["error"] = cbErr.Error()
			} else {
				out["callback_configured"] = true
				out["callback_host"] = cb
			}
			return jsonResult(out)
		},
	})
}

func (s *Server) tunnelDeployTool() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "tunnel_deploy",
		Description: "【隧道·deploy】按计划登记并进程内拉起一条 socks 或 portfwd 隧道（adapter=chisel|suo5，默认 chisel）。" +
			"二进制按需（ARTEX_CHISEL_PATH / ARTEX_SUO5_PATH 或 data/tools 下的同名文件），缺失则台账标 error，非默认必装。" +
			"只对环回入口做健康检查，不向真实目标打洞。用完请 tunnel_teardown。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"session_id": map[string]any{"type": "integer", "description": "经哪条立足点会话部署"},
				"kind":       map[string]any{"type": "string", "description": "socks | portfwd"},
				"adapter":    map[string]any{"type": "string", "description": "chisel | suo5，默认 chisel"},
				"target":     map[string]any{"type": "string", "description": "portfwd 时必填，host:port"},
			},
			"required": []any{"session_id", "kind"},
		},
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			if s.tunnels == nil || s.tunnels.store == nil {
				return actool.Errorf("隧道台账未就绪"), nil
			}
			var a struct {
				SessionID int64  `json:"session_id"`
				Kind      string `json:"kind"`
				Adapter   string `json:"adapter"`
				Target    string `json:"target"`
			}
			_ = json.Unmarshal(in, &a)
			if _, err := s.lookupSession(a.SessionID); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			kind := strings.TrimSpace(a.Kind)
			adapter := strings.ToLower(strings.TrimSpace(a.Adapter))
			if adapter == "" || adapter == "auto" {
				adapter = tunnel.AdapterChisel
			}
			if adapter != tunnel.AdapterChisel && adapter != tunnel.AdapterSuo5 {
				return actool.Errorf(fmt.Sprintf("adapter 非法：%q（chisel|suo5）", a.Adapter)), nil
			}
			if adapter == tunnel.AdapterSuo5 && kind != tunnel.KindSocks {
				return actool.Errorf("suo5 适配器只支持 kind=socks；portfwd 请用 chisel"), nil
			}
			cbHost, err := callbackHost()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			ri := agent.RunInfoFrom(ctx)
			opts := &tunnel.PlanOpts{
				TaskID:       ri.TaskID,
				ViaSessionID: a.SessionID,
				CallbackHost: cbHost,
				DataDir:      s.tunnels.dataDir,
				CanListen:    tunnel.CanListen,
			}
			opts.PortMin, opts.PortMax, err = tunnel.ParsePortRange(config.TunnelPortRange())
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			opts.UsedPorts, err = s.occupiedPorts(ctx)
			if err != nil {
				return actool.Errorf("端口占用汇总失败：" + err.Error()), nil
			}
			var plan *tunnel.Plan
			switch kind {
			case tunnel.KindSocks:
				plan, err = tunnel.PlanSocks(opts)
			case tunnel.KindPortfwd:
				host, portStr, perr := net.SplitHostPort(strings.TrimSpace(a.Target))
				if perr != nil || host == "" {
					return actool.Errorf("portfwd 需要 target=host:port"), nil
				}
				port, perr := strconv.Atoi(portStr)
				if perr != nil || port <= 0 {
					return actool.Errorf("target 端口非法： " + portStr), nil
				}
				opts.TargetHost, opts.TargetPort = host, port
				plan, err = tunnel.PlanPortfwd(opts)
			default:
				return actool.Errorf("kind 必填：socks | portfwd"), nil
			}
			if err != nil {
				return actool.Errorf("计划生成失败：" + err.Error()), nil
			}
			plan.Adapter = adapter
			if s.tunnels.mgr == nil {
				return actool.Errorf("隧道运行时未就绪"), nil
			}
			rec, derr := s.tunnels.mgr.Deploy(ctx, plan)
			if rec == nil && derr != nil {
				return actool.Errorf("部署失败：" + derr.Error()), nil
			}
			if rec == nil {
				return actool.Errorf("部署失败：无台账行"), nil
			}
			out := map[string]any{
				"tunnel_id": rec.ID,
				"kind":      rec.Kind,
				"adapter":   rec.Adapter,
				"state":     rec.State,
				"note":      "用完请 tunnel_teardown。外部二进制按需，非默认必装；本刀只对环回入口探活。",
			}
			if rec.Error != "" {
				out["error"] = rec.Error
			}
			if plan.Kind == tunnel.KindSocks && plan.SocksPort > 0 {
				addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(plan.SocksPort))
				out["socks_addr"] = addr
				out["socks_url"] = "socks5://" + addr
			} else if plan.Kind == tunnel.KindPortfwd {
				out["forward_addr"] = net.JoinHostPort("127.0.0.1", strconv.Itoa(plan.LocalPort))
				out["forward_to"] = net.JoinHostPort(plan.TargetHost, strconv.Itoa(plan.TargetPort))
			}
			if derr != nil {
				return jsonResult(out)
			}
			return jsonResult(out)
		},
	})
}

func (s *Server) tunnelListTool() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "tunnel_list",
		Description: "【隧道·list】列本平台隧道台账：id/类型/适配器/状态/入口端口/目标/经哪条会话/错误信息。任务内默认只列本任务的。",
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			if s.tunnels == nil || s.tunnels.store == nil {
				return actool.Errorf("隧道台账未就绪"), nil
			}
			ri := agent.RunInfoFrom(ctx)
			var recs []*db.TunnelRecord
			var err error
			if ri.TaskID > 0 {
				recs, err = s.tunnels.store.ListByTask(ctx, ri.TaskID)
			} else {
				recs, err = s.tunnels.store.List(ctx)
			}
			if err != nil {
				return actool.Errorf("台账读取失败：" + err.Error()), nil
			}
			out := []map[string]any{}
			for _, r := range recs {
				var p tunnel.Plan
				_ = json.Unmarshal(r.DeployParams, &p)
				row := map[string]any{
					"tunnel_id":      r.ID,
					"kind":           r.Kind,
					"adapter":        r.Adapter,
					"state":          r.State,
					"listen_port":    r.ListenPort,
					"via_session_id": r.ViaSessionID,
					"last_check":     r.LastCheck.Format("2006-01-02 15:04:05"),
				}
				if r.Kind == tunnel.KindSocks && p.SocksPort > 0 {
					row["socks_addr"] = net.JoinHostPort("127.0.0.1", strconv.Itoa(p.SocksPort))
				}
				if r.Kind == tunnel.KindPortfwd {
					row["forward_addr"] = net.JoinHostPort("127.0.0.1", strconv.Itoa(p.LocalPort))
					row["target"] = net.JoinHostPort(r.TargetHost, strconv.Itoa(r.TargetPort))
				}
				if r.Error != "" {
					row["error"] = r.Error
				}
				out = append(out, row)
			}
			return jsonResult(map[string]any{"tunnels": out, "count": len(out)})
		},
	})
}

func (s *Server) tunnelTeardownTool() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "tunnel_teardown",
		Description: "【隧道·teardown】回收一条隧道：杀掉本平台拉起的适配器进程，台账标 stopped，并刷新该任务 MITM 上游。用完必须调这个。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"tunnel_id": map[string]any{"type": "integer", "description": "tunnel_deploy/tunnel_list 返回的隧道 id"},
			},
			"required": []any{"tunnel_id"},
		},
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				TunnelID int64 `json:"tunnel_id"`
			}
			_ = json.Unmarshal(in, &a)
			if a.TunnelID <= 0 {
				return actool.Errorf("tunnel_id 必填且 > 0"), nil
			}
			if err := s.teardownTunnel(ctx, a.TunnelID); err != nil {
				return actool.Errorf("回收失败：" + err.Error()), nil
			}
			return jsonResult(map[string]any{"tunnel_id": a.TunnelID, "state": db.TunnelStopped})
		},
	})
}

func (s *Server) seedTunnelTools() {
	if s.tunnels == nil || s.m == nil || s.m.PG() == nil {
		return
	}
	workerAgents, _ := json.Marshal([]string{"worker"})
	for _, t := range s.tunnelTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.PG().SeedTool(t.Name(), t.Description(), schema, workerAgents); err != nil {
			log.Printf("[tools] seed %s 失败： %v", t.Name(), err)
		}
	}
}

// GET /api/tunnels?task_id= — 台账列表（含 stopped，JWT 之后）。
func (s *Server) intranetListTunnels(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.PG() == nil {
		writeErr(w, 503, "隧道台账未就绪(DB 未连接)")
		return
	}
	taskID, ok := parseTaskIDQuery(w, r)
	if !ok {
		return
	}
	store := db.NewTunnelStore(s.m.PG())
	var recs []*db.TunnelRecord
	var err error
	if taskID > 0 {
		recs, err = store.ListByTask(r.Context(), taskID)
	} else {
		recs, err = store.List(r.Context())
	}
	if err != nil {
		writeErr(w, 500, "隧道台账读取失败: "+err.Error())
		return
	}
	items := []*db.TunnelRecord{}
	items = append(items, recs...)
	writeJSON(w, 200, map[string]any{"items": items})
}

// POST /api/tunnels/{id}/teardown — 回收隧道（JWT 之后）。
func (s *Server) intranetTeardownTunnel(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := s.teardownTunnel(r.Context(), id); err != nil {
		s.auditIntranet(r, "tunnel_teardown id=%d 失败: %v", id, err)
		writeErr(w, 502, "回收失败: "+err.Error())
		return
	}
	s.auditIntranet(r, "tunnel_teardown id=%d 成功", id)
	writeJSON(w, 200, map[string]any{"tunnel_id": id, "state": db.TunnelStopped})
}

func collectTopoTunnels(ctx context.Context, live tunnelLiveLister, taskID int64) []topoTunnel {
	if live == nil {
		return nil
	}
	var recs []*db.TunnelRecord
	var err error
	if taskID > 0 {
		recs, err = live.ListByTask(ctx, taskID)
	} else if store, ok := live.(interface {
		List(context.Context) ([]*db.TunnelRecord, error)
	}); ok {
		recs, err = store.List(ctx)
	} else {
		return nil
	}
	if err != nil {
		return nil
	}
	out := make([]topoTunnel, 0, len(recs))
	for _, r := range recs {
		if r == nil {
			continue
		}
		out = append(out, topoTunnel{
			ID: r.ID, Kind: r.Kind, TargetHost: r.TargetHost, TargetPort: r.TargetPort,
			ViaSessionID: r.ViaSessionID, State: r.State,
		})
	}
	return out
}

func callbackHostForTopo() string {
	addr := strings.TrimSpace(config.CallbackAddr())
	if addr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		if u, uerr := url.Parse(addr); uerr == nil && u.Hostname() != "" {
			return u.Hostname()
		}
		return addr
	}
	return host
}
