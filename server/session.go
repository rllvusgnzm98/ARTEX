// session.go 装配立足点会话子系统：进程内 Registry + DB 恢复 + 默认绑给
// worker 的 register_session / session_recon。HTTP 会话只对接已经存在的立足点，
// 不生成载荷。list/probe/read 以及受登录保护的 exec/write 走控制台 API
// （见 intranet.go），不作为 worker 默认工具。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/session"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// maxSessionToolOutput 是 session 控制台 exec/read 返回给调用方的输出上限（64KB)。
const maxSessionToolOutput = 64 * 1024

func truncateOutput(s string) string {
	if len(s) <= maxSessionToolOutput {
		return s
	}
	return s[:maxSessionToolOutput] + fmt.Sprintf("\n…[输出截断：共 %d 字节，仅返回前 %d]", len(s), maxSessionToolOutput)
}

const (
	sessionStaleProbeAge   = 24 * time.Hour
	startupProbePerTimeout = 8 * time.Second
	startupProbeBudget     = 60 * time.Second
	startupProbeMaxConc    = 8
)

// isLogicalSessionKind reports whether kind is a lightweight logical session
// (winrm / ssh / msf_bind) that persists connection metadata without an active HTTP probe.
func isLogicalSessionKind(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "winrm", "ssh", "msf_bind":
		return true
	default:
		return false
	}
}

// sessionNeedsStartupProbe 是启动探活的阈值判定（纯函数，可测）:
// alive 且非逻辑会话且 last_beat 距 now 超过 age 才需要探活；恰好在边界上不算陈旧。
func sessionNeedsStartupProbe(rec *db.SessionRecord, now time.Time, age time.Duration) bool {
	return rec != nil && rec.Status == db.SessionAlive && !isLogicalSessionKind(rec.Kind) && now.Sub(rec.LastBeat) > age
}

// initSessions 建会话注册表与落库访问层，并从 DB 恢复存活的 HTTP 会话。
// 恢复后对陈旧（last_beat 超 sessionStaleProbeAge）会话做一次异步启动探活：
// 失败诚实标 dead。失败只记日志，不拖垮启动。逻辑连接（winrm/ssh/msf_bind）保持台账，不作 HTTP 探活。
func (s *Server) initSessions() {
	if s.m.pg == nil {
		return
	}
	s.sessStore = db.NewSessionStore(s.m.pg, s.jwtKey)
	s.sessReg = session.NewRegistry()
	recs, err := s.sessStore.List(s.ctx, db.SessionAlive)
	if err != nil {
		log.Printf("[session] 启动恢复读取失败: %v", err)
		return
	}
	restored := 0
	for _, rec := range recs {
		if isLogicalSessionKind(rec.Kind) {
			log.Printf("[session] 会话 %d 逻辑连接(%s)保持台账记录，跳过启动探活", rec.ID, rec.Kind)
			continue
		}
		var sec session.Secret
		if err := json.Unmarshal(rec.Secret, &sec); err != nil {
			log.Printf("[session] 会话 %d secret 解析失败，跳过: %v", rec.ID, err)
			continue
		}
		var sh session.Session
		switch rec.Kind {
		case "http_php", "http_phpcmd", "http_jsp", "http_aspx", "http_phpenc", "http_jspenc":
			sh, err = session.RestoreHTTPShell(rec.ID, sec)
		case "emp3r0r":
			if s.emp3r0r == nil || s.emp3r0r.client == nil {
				log.Printf("[session] 会话 %d emp3r0r 未启用/桥接不可用，诚实标 dead", rec.ID)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_ = s.sessStore.UpdateStatus(ctx, rec.ID, db.SessionDead)
				cancel()
				continue
			}
			sh, err = session.RestoreEmp3r0r(rec.ID, sec, s.emp3r0r.client)
			if err == nil && s.emp3r0r != nil {
				s.emp3r0r.mu.Lock()
				s.emp3r0r.seen[sec.AgentTag] = rec.ID
				s.emp3r0r.mu.Unlock()
			}
		default:
			log.Printf("[session] 会话 %d 类型 %s 本期不支持恢复，跳过", rec.ID, rec.Kind)
			continue
		}
		if err != nil {
			log.Printf("[session] 会话 %d 恢复失败，跳过: %v", rec.ID, err)
			continue
		}
		s.sessReg.Add(sh)
		restored++
	}
	if len(recs) > 0 {
		log.Printf("[session] 启动恢复：%d/%d 条存活会话已载入注册表", restored, len(recs))
	}
	go s.startupProbeStale(recs)
}

func (s *Server) startupProbeStale(recs []*db.SessionRecord) {
	s.startupProbeStaleAt(recs, time.Now())
}

// startupProbeStaleAt 对陈旧 alive 会话并发探活：成功刷新 last_beat，失败诚实标 dead。
// now 由调用方传入，测试用固定时间 fixture，避免依赖墙上时钟。
func (s *Server) startupProbeStaleAt(recs []*db.SessionRecord, now time.Time) {
	parent := s.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, startupProbeBudget)
	defer cancel()
	sem := make(chan struct{}, startupProbeMaxConc)
	var wg sync.WaitGroup
	var aliveN, deadN atomic.Int64
	probed := 0
	for _, rec := range recs {
		if !sessionNeedsStartupProbe(rec, now, sessionStaleProbeAge) {
			continue
		}
		sess, ok := s.sessReg.Get(rec.ID)
		if !ok {
			continue
		}
		probed++
		wg.Add(1)
		go func(id int64, sess session.Session) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			pctx, pcancel := context.WithTimeout(ctx, startupProbePerTimeout)
			err := sess.Test(pctx)
			pcancel()
			dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer dcancel()
			if err != nil {
				if uerr := s.sessStore.UpdateStatus(dctx, id, db.SessionDead); uerr != nil {
					log.Printf("[session] 启动探活：会话 %d 标 dead 落库失败： %v", id, uerr)
				}
				deadN.Add(1)
				return
			}
			_ = s.sessStore.UpdateStatus(dctx, id, db.SessionAlive)
			s.sessStore.Touch(dctx, id)
			aliveN.Add(1)
		}(rec.ID, sess)
	}
	wg.Wait()
	if probed > 0 {
		log.Printf("[session] 启动探活：%d 活 %d 死（共探 %d 条陈旧会话）",
			aliveN.Load(), deadN.Load(), probed)
	}
}

func sessionPerm(context.Context, json.RawMessage, permission.Context) permission.Decision {
	return permission.Allowed()
}

// sessionTools 返回默认绑给 worker 的立足点工具：仅登记与只读侦察。
// sessReg 为 nil（DB 未就绪）时不提供。
func (s *Server) sessionTools() []actool.CoreTool {
	if s.sessReg == nil || s.sessStore == nil {
		return nil
	}
	return []actool.CoreTool{
		s.registerSessionTool(),
		s.sessionReconTool(),
	}
}

// registerSessionTool 把已经存在的 HTTP 立足点或逻辑连接（winrm/ssh/msf_bind）登记为平台管理的会话：
// HTTP 类型先做无害连通性探测（支持 GET/POST），成功才落库；失败返回原因，不伪造成功。
// 逻辑类型（winrm/ssh/msf_bind）直接将连接元数据落库，不发起 HTTP 探针。
// 本工具不生成任何载荷，只对接已经存在的立足点。
func (s *Server) registerSessionTool() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "register_session",
		Description: "把已经存在的 HTTP 立足点或轻量逻辑连接（winrm/ssh/msf_bind）登记为平台管理的会话。" +
			"HTTP 通道类型：php / phpcmd / jsp / aspx / auto（自动探测），可选 method=POST|GET；" +
			"已有加密通道可传 lang=phpenc|jspenc 且提供 secret（既有密钥）。" +
			"逻辑连接类型：传 kind=winrm|ssh|msf_bind（附 host/url、port、username、method、notes），直接登记台账不发 HTTP 探针。" +
			"本工具不生成任何载荷，只对接已经存在的立足点。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"url":           strParam("立足点完整 URL，含协议（HTTP 通道必填；逻辑会话 winrm/ssh/msf_bind 未传 host 时必填）"),
				"kind":          strParam("可选，会话类型：http（默认，走 HTTP 探针）| winrm | ssh | msf_bind（轻量逻辑连接登记，不发 HTTP 探针）"),
				"method":        strParam("可选，HTTP 通道请求方式：POST（默认）| GET；逻辑会话可存连接/认证方法说明"),
				"host":          strParam("可选，目标主机 IP/域名（逻辑会话 winrm/ssh/msf_bind 未传 url 时使用）"),
				"port":          map[string]any{"type": "integer", "description": "可选，连接端口（用于逻辑会话 winrm/ssh/msf_bind）"},
				"username":      strParam("可选，连接用户名（用于逻辑会话 winrm/ssh/msf_bind）"),
				"notes":         strParam("可选，连接备注/复用说明（用于逻辑会话 winrm/ssh/msf_bind）"),
				"password":      strParam("连接参数名（POST/GET 字段名，默认 cmd；加密通道不需要；逻辑会话可选存连接口令）"),
				"lang":          strParam("HTTP 通道类型：php / phpcmd / jsp / aspx / auto（默认 auto）；phpenc / jspenc（已有加密通道）"),
				"secret":        strParam("已有加密通道的密钥（仅 phpenc/jspenc 必填）"),
				"credential_id": map[string]any{"type": "integer", "description": "可选。仅当平台探针成功并完成登记后，若该凭据属于本任务或已继承进本任务，才标记为已验证。0 或缺省不处理。模型自称已验证不会被采纳；不属于本任务的 id 只附加非致命提示，不影响登记成功。"},
			},
		},
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				URL          string `json:"url"`
				Kind         string `json:"kind"`
				Method       string `json:"method"`
				Host         string `json:"host"`
				Port         int    `json:"port"`
				Username     string `json:"username"`
				Notes        string `json:"notes"`
				Password     string `json:"password"`
				Lang         string `json:"lang"`
				Secret       string `json:"secret"`
				CredentialID int64  `json:"credential_id"`
			}
			_ = json.Unmarshal(in, &a)
			a.URL = strings.TrimSpace(a.URL)
			kind := strings.ToLower(strings.TrimSpace(a.Kind))
			if kind == "" && isLogicalSessionKind(a.Lang) {
				kind = strings.ToLower(strings.TrimSpace(a.Lang))
			}

			if isLogicalSessionKind(kind) {
				return s.registerLogicalSession(ctx, kind, a.URL, a.Host, a.Port, a.Username, a.Password, a.Method, a.Lang, a.Notes)
			}
			if kind != "" && kind != "http" && !strings.HasPrefix(kind, "http_") {
				return actool.Errorf(fmt.Sprintf("不支持的会话类型 %q（支持 http / winrm / ssh / msf_bind）", a.Kind)), nil
			}
			if a.URL == "" {
				return actool.Errorf("url 为必填参数"), nil
			}
			method := strings.ToUpper(strings.TrimSpace(a.Method))
			if method != "" && method != "GET" && method != "POST" {
				return actool.Errorf(fmt.Sprintf("method 仅支持 GET 或 POST，实际 %q", a.Method)), nil
			}
			warn, roeErr := s.sessionRoECheck(ctx, a.URL)
			if roeErr != nil {
				return actool.Errorf(roeErr.Error()), nil
			}
			var sh *session.HTTPShell
			var info session.ProbeInfo
			var err error
			if a.Lang == "phpenc" || a.Lang == "jspenc" {
				if method == "GET" {
					return actool.Errorf(withRoEWarn(warn, "加密通道（"+a.Lang+"）仅支持 POST")), nil
				}
				if strings.TrimSpace(a.Secret) == "" {
					a.Secret = strings.TrimSpace(a.Password)
				}
				if a.Secret == "" {
					return actool.Errorf(withRoEWarn(warn, "加密通道（"+a.Lang+"）登记需要既有密钥：把 secret（或 password）参数填为已有密钥")), nil
				}
				sh, info, err = session.ProbeEnc(ctx, a.URL, a.Lang, a.Secret)
			} else {
				sh, info, err = session.ProbeWithMethod(ctx, a.URL, a.Password, a.Lang, method)
			}
			if err != nil {
				return actool.Errorf(withRoEWarn(warn, "探测失败："+err.Error())), nil
			}
			epMethod := strings.ToUpper(strings.TrimSpace(sh.Method()))
			if epMethod == "" {
				epMethod = "POST"
			}
			secret, _ := json.Marshal(sh.Secret())
			ri := agent.RunInfoFrom(ctx)
			rec := &db.SessionRecord{
				Kind: info.Kind, URL: a.URL, Secret: secret, Lang: info.Lang,
				Status: db.SessionAlive, CreatedByTask: ri.TaskID, CreatedByIntent: ri.IntentID,
			}
			id, err := s.sessStore.Create(ctx, rec)
			if err != nil {
				return actool.Errorf(withRoEWarn(warn, "会话落库失败："+err.Error())), nil
			}
			sh.SetID(id)
			s.sessReg.Add(sh)
			if added, total := agent.ExtendWorkerProgressFromContext(ctx, 5*time.Minute); added > 0 {
				log.Printf("[session] task %d intent #%d 建立立足点会话，运行预算续期 +%s（累计 +%s）", ri.TaskID, ri.IntentID, added, total)
			}
			var assetID int64
			if s.m != nil && s.m.Assets() != nil {
				if aid, aerr := s.m.Assets().UpsertEndpoint(db.UpsertEndpointReq{
					URL: a.URL, Method: epMethod, TaskID: ri.TaskID,
				}); aerr == nil {
					assetID = aid
					s.sessStore.SetHostAsset(ctx, id, aid)
				}
			}
			out := map[string]any{
				"session_id": id, "kind": info.Kind, "lang": info.Lang, "method": epMethod,
				"variant": info.Variant, "funcs": info.Funcs, "platform": info.Platform,
				"shell_type": shellTypeLabel(info), "message": registerMessage(info),
			}
			if assetID > 0 {
				out["host_asset_id"] = assetID
			}
			if strings.HasPrefix(info.Lang, "php") && info.Variant != "cmd" {
				out["disable_functions"] = info.DisableFunctions
				out["mail"], out["putenv"] = info.Mail, info.Putenv
			}
			if len(info.Funcs) == 0 && strings.HasPrefix(info.Lang, "php") && info.Variant != "cmd" {
				out["warning"] = "目标 PHP 禁用了全部命令执行函数（disable_functions）；session_exec 不可用，文件读写仍可用"
			}
			if warn != "" {
				out["roe_warning"] = warn
			}
			// 置位只跟这次已经成功的探针走。不读模型给出的 verified/说明文本。
			if note, ok := s.observeCredentialVerified(ctx, ri.TaskID, a.CredentialID); note != "" {
				out["credential_warning"] = note
			} else if ok {
				out["credential_verified"] = true
			}
			return jsonResult(out)
		},
	})
}

type logicalSessionSecret struct {
	Kind     string `json:"kind"`
	URL      string `json:"url"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Method   string `json:"method,omitempty"`
	Notes    string `json:"notes,omitempty"`
}

func resolveLogicalSessionEndpoint(kind, rawURL, rawHost string, rawPort int) (sessURL, host string, port int) {
	host = strings.TrimSpace(rawHost)
	port = rawPort
	rawURL = strings.TrimSpace(rawURL)
	if rawURL != "" {
		if strings.Contains(rawURL, "://") {
			if u, err := url.Parse(rawURL); err == nil {
				if host == "" {
					host = u.Hostname()
				}
				if port <= 0 && u.Port() != "" {
					if p, perr := strconv.Atoi(u.Port()); perr == nil && p > 0 {
						port = p
					}
				}
				sessURL = rawURL
			}
		} else {
			if h, pStr, err := net.SplitHostPort(rawURL); err == nil {
				if host == "" {
					host = h
				}
				if port <= 0 {
					if p, perr := strconv.Atoi(pStr); perr == nil && p > 0 {
						port = p
					}
				}
			} else if host == "" {
				host = rawURL
			}
		}
	}
	if sessURL == "" && host != "" {
		if port > 0 {
			sessURL = fmt.Sprintf("%s://%s", kind, net.JoinHostPort(host, strconv.Itoa(port)))
		} else if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
			sessURL = fmt.Sprintf("%s://[%s]", kind, host)
		} else {
			sessURL = fmt.Sprintf("%s://%s", kind, host)
		}
	}
	return sessURL, host, port
}

func (s *Server) registerLogicalSession(ctx context.Context, kind, rawURL, rawHost string, rawPort int, username, password, method, lang, notes string) (actool.Result, error) {
	if s.sessStore == nil {
		return actool.Errorf("会话子系统未就绪"), nil
	}
	sessURL, host, port := resolveLogicalSessionEndpoint(kind, rawURL, rawHost, rawPort)
	if sessURL == "" || host == "" {
		return actool.Errorf(fmt.Sprintf("逻辑会话(%s)登记需要提供 host 或 url", kind)), nil
	}
	warn, roeErr := s.sessionRoECheck(ctx, sessURL)
	if roeErr != nil {
		return actool.Errorf(roeErr.Error()), nil
	}
	username = strings.TrimSpace(username)
	method = strings.TrimSpace(method)
	notes = strings.TrimSpace(notes)
	langVal := strings.TrimSpace(lang)
	if langVal == "" {
		langVal = kind
	}
	sec := logicalSessionSecret{
		Kind:     kind,
		URL:      sessURL,
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
		Method:   method,
		Notes:    notes,
	}
	secretBytes, err := json.Marshal(sec)
	if err != nil {
		return actool.Errorf(fmt.Sprintf("会话参数编码失败：%v", err)), nil
	}
	ri := agent.RunInfoFrom(ctx)
	rec := &db.SessionRecord{
		Kind:            kind,
		URL:             sessURL,
		Secret:          secretBytes,
		Lang:            langVal,
		Status:          db.SessionAlive,
		CreatedByTask:   ri.TaskID,
		CreatedByIntent: ri.IntentID,
	}
	id, err := s.sessStore.Create(ctx, rec)
	if err != nil {
		return actool.Errorf(withRoEWarn(warn, "会话落库失败："+err.Error())), nil
	}
	if added, total := agent.ExtendWorkerProgressFromContext(ctx, 5*time.Minute); added > 0 {
		log.Printf("[session] task %d intent #%d 登记逻辑立足点(%s)，运行预算续期 +%s（累计 +%s）", ri.TaskID, ri.IntentID, kind, added, total)
	}
	var assetID int64
	if s.m != nil && s.m.Assets() != nil && net.ParseIP(host) != nil {
		if aid, aerr := s.m.Assets().UpsertIP(db.UpsertIPReq{
			IP: host, TaskID: ri.TaskID,
		}); aerr == nil {
			assetID = aid
			s.sessStore.SetHostAsset(ctx, id, aid)
		}
	}
	out := map[string]any{
		"session_id": id,
		"kind":       kind,
		"lang":       langVal,
		"url":        sessURL,
		"host":       host,
		"status":     db.SessionAlive,
		"logical":    true,
		"message":    fmt.Sprintf("已登记 %s 逻辑连接（未执行 HTTP 探针），后续单兵可通过台账发现并复用", kind),
	}
	if port > 0 {
		out["port"] = port
	}
	if username != "" {
		out["username"] = username
	}
	if method != "" {
		out["method"] = method
	}
	if notes != "" {
		out["notes"] = notes
	}
	if assetID > 0 {
		out["host_asset_id"] = assetID
	}
	if warn != "" {
		out["roe_warning"] = warn
	}
	return jsonResult(out)
}

func shellTypeLabel(info session.ProbeInfo) string {
	switch {
	case strings.HasSuffix(info.Lang, "enc"):
		return "enc"
	case info.Lang == "phpcmd" || info.Variant == "cmd":
		return "cmd"
	case info.Lang == "php":
		return "eval"
	default:
		return info.Lang
	}
}

func registerMessage(info session.ProbeInfo) string {
	switch shellTypeLabel(info) {
	case "cmd":
		return "已登记为命令执行通道：后续控制台 exec 直接透传 shell 命令（哨兵同步）"
	case "enc":
		return "已登记为加密会话（" + info.Lang + "）：全密文通信"
	case "eval":
		if info.DisableFunctions {
			return "已登记为 PHP eval 通道；disable_functions 全禁，命令执行不可用，仅文件读写"
		}
		return "已登记为 PHP eval 通道（" + info.Variant + " 族）"
	default:
		return "已登记为 " + info.Lang + " 会话"
	}
}

// lookupSession 从注册表取会话；查无返回带语义错误。
func (s *Server) lookupSession(id int64) (session.Session, error) {
	if id <= 0 {
		return nil, fmt.Errorf("session_id 必填且 > 0")
	}
	if s.sessReg == nil {
		return nil, fmt.Errorf("会话子系统未就绪")
	}
	sess, ok := s.sessReg.Get(id)
	if !ok {
		return nil, fmt.Errorf("session %d 不存在（未登记/已删除/进程重启后恢复失败）,请用 register_session 重新登记", id)
	}
	return sess, nil
}

// seedSessionTools 把默认会话工具 seed 进 tools 表、默认绑定 worker。
// 与既有 SeedTool 首插入语义一致：老库的用户编辑不被覆盖。
func (s *Server) seedSessionTools() {
	if s.m == nil || s.m.PG() == nil {
		return
	}
	workerAgents, _ := json.Marshal([]string{"worker"})
	for _, t := range s.sessionTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.PG().SeedTool(t.Name(), t.Description(), schema, workerAgents); err != nil {
			log.Printf("[tools] seed %s 失败： %v", t.Name(), err)
		}
		s.syncBuiltinToolSchema(t.Name(), t.Description(), schema)
	}
}
