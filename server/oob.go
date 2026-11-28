package server

import (
	"context"
	"errors"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/oob"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

func (s *Server) initOOB(dataDir string) {
	m, err := oob.New(s.ctx, filepath.Join(dataDir, "oob"))
	if err != nil {
		log.Printf("[oob] disabled: %v", err)
		return
	}
	m.OnEvent = s.recordOOBEvent
	s.oob = m
	log.Printf("[oob] 托管回调服务已就绪: /o/<token> (TTL 默认 %v, 上限 %v)", oob.DefaultTTL, oob.MaxTTL)
}

// SetOOBBaseURL sets the external base URL used for oob_allocate links.
// It prefers config.CallbackAddr() when configured, falling back to the main HTTP listen address.
func (s *Server) SetOOBBaseURL(addr string) {
	if s.oob == nil {
		return
	}
	if cb := strings.TrimSpace(config.CallbackAddr()); cb != "" {
		if strings.Contains(cb, "://") {
			s.oob.SetBaseURL(cb)
			return
		}
		if strings.Contains(cb, ":") {
			s.oob.SetBaseURL("http://" + cb)
			return
		}
		// CallbackAddr is host/IP only -> inherit listen port from addr.
		if _, port, ok := strings.Cut(addr, ":"); ok && port != "" {
			s.oob.SetBaseURL("http://" + cb + ":" + port)
			return
		}
		s.oob.SetBaseURL("http://" + cb)
		return
	}
	host := addr
	if strings.HasPrefix(host, "0.0.0.0") {
		host = strings.Replace(host, "0.0.0.0", "127.0.0.1", 1)
	} else if strings.HasPrefix(host, ":") {
		host = "127.0.0.1" + host
	}
	s.oob.SetBaseURL("http://" + host)
}

func oobTokenPrefix(token string) string {
	if len(token) <= tokenLogPrefix {
		return token
	}
	return token[:tokenLogPrefix]
}

func (s *Server) recordOOBEvent(ev oob.Event) {
	e := ev.Entry
	prefix := oobTokenPrefix(e.Token)
	summary := fmt.Sprintf("oob %s: %s (token=%s… driver=%s)", ev.Kind, orDash(e.Label), prefix, e.Driver)
	detail := fmt.Sprintf("token=%s… label=%s driver=%s hits=%d expires_at=%s",
		prefix, orDash(e.Label), e.Driver, e.Hits, e.ExpiresAt.Format(time.RFC3339))
	if ev.Kind == oob.EventHit && ev.Interaction != nil {
		summary = fmt.Sprintf("oob hit #%d: %s (%s %s from %s)",
			ev.Interaction.Seq, orDash(e.Label), ev.Interaction.Protocol, orDash(ev.Interaction.Method), orDash(ev.Interaction.RemoteIP))
		detail = fmt.Sprintf("token=%s… seq=%d protocol=%s method=%s path=%s remote=%s hits=%d",
			prefix, ev.Interaction.Seq, ev.Interaction.Protocol, ev.Interaction.Method, ev.Interaction.Path, ev.Interaction.RemoteIP, e.Hits)
	}
	log.Printf("[oob] task=%s %s", orDash(e.TaskID), summary)
	if e.TaskID == "" || s.m == nil {
		return
	}
	s.m.mu.Lock()
	t := s.m.tasks[e.TaskID]
	s.m.mu.Unlock()
	if t == nil || t.Store == nil {
		return
	}
	_, _ = t.Store.AppendActivity(db.Activity{
		Worker: "system", Kind: "text", Tool: "oob_poll",
		Summary: summary,
		Detail:  detail,
	})
}

// oobCallback handles public unauthenticated OOB HTTP requests at /o/{token}[/{rest...}].
func (s *Server) oobCallback(w http.ResponseWriter, r *http.Request) {
	if s.oob == nil {
		http.NotFound(w, r)
		return
	}
	s.oob.HandleHTTP(w, r, r.PathValue("token"), r.PathValue("rest"))
}

// --- Management HTTP API (behind JWT) ---

func (s *Server) oobCreate(w http.ResponseWriter, r *http.Request) {
	if s.oob == nil {
		writeErr(w, 503, "oob service disabled")
		return
	}
	var req struct {
		TaskID       string `json:"task_id"`
		Label        string `json:"label"`
		TTLMinutes   int    `json:"ttl_minutes"`
		Driver       string `json:"driver"`
		StatusCode   int    `json:"status_code"`
		ContentType  string `json:"content_type"`
		ResponseBody string `json:"response_body"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	e, err := s.oob.Allocate(oob.AllocateOpts{
		TaskID:       strings.TrimSpace(req.TaskID),
		Label:        req.Label,
		TTL:          time.Duration(req.TTLMinutes) * time.Minute,
		Driver:       req.Driver,
		StatusCode:   req.StatusCode,
		ContentType:  req.ContentType,
		ResponseBody: req.ResponseBody,
	})
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, e)
}

func (s *Server) oobList(w http.ResponseWriter, r *http.Request) {
	if s.oob == nil {
		writeJSON(w, 200, []oob.Entry{})
		return
	}
	taskID := strings.TrimSpace(r.URL.Query().Get("task_id"))
	writeJSON(w, 200, s.oob.List(taskID))
}

func (s *Server) oobPollHTTP(w http.ResponseWriter, r *http.Request) {
	if s.oob == nil {
		writeErr(w, 503, "oob service disabled")
		return
	}
	q := r.URL.Query()
	taskID := strings.TrimSpace(q.Get("task_id"))
	sinceSeq, _ := strconv.ParseInt(q.Get("since_seq"), 10, 64)
	waitSec, _ := strconv.Atoi(q.Get("wait_seconds"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	events, entry, err := s.oob.Poll(r.Context(), taskID, r.PathValue("token"), sinceSeq, time.Duration(waitSec)*time.Second, limit)
	if err != nil {
		if errors.Is(err, oob.ErrNotFound) {
			writeErr(w, 404, err.Error())
			return
		}
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"entry":        entry,
		"interactions": events,
	})
}

func (s *Server) oobDelete(w http.ResponseWriter, r *http.Request) {
	if s.oob == nil {
		writeErr(w, 503, "oob service disabled")
		return
	}
	taskID := strings.TrimSpace(r.URL.Query().Get("task_id"))
	tok := r.PathValue("token")
	if !s.oob.Delete(taskID, tok) {
		writeErr(w, 404, "oob endpoint not found")
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": tok})
}

// --- Host Tools (oob_allocate / oob_poll) ---

func (s *Server) oobTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.oobAllocateTool(),
		s.oobPollTool(),
	}
}

func (s *Server) oobAllocateTool() actool.CoreTool {
	allow := func(context.Context, json.RawMessage, permission.Context) permission.Decision {
		return permission.Allowed()
	}
	return actool.Build(actool.Spec{
		Name: "oob_allocate",
		Description: "向平台申请一个托管的带外（OOB）回调接收端点，用于盲 XSS / SSRF / XXE / RCE / 管理员机器人触发验证。" +
			"返回唯一回调 URL（/o/<token>，或可选 interactsh-client 域名），跨意图持久化保留，无需自己起 python HTTP 服务或占 80 端口。" +
			"支持自定义响应体（如返回 stage-2 JS）与默认 permissive CORS。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"label":                 map[string]any{"type": "string", "description": "简短用途标签（如 xss-admin-bot / ssrf-metadata）"},
				"ttl_minutes":           map[string]any{"type": "integer", "description": "存活分钟数（默认 120，上限 1440）"},
				"driver":                map[string]any{"type": "string", "enum": []any{"http", "interactsh"}, "description": "http（默认，内置 /o/<token>）或 interactsh（需已安装 interactsh-client，支持 DNS/HTTP）"},
				"status_code":           map[string]any{"type": "integer", "description": "HTTP 回调响应状态码（默认 200）"},
				"response_content_type": map[string]any{"type": "string", "description": "HTTP 回调响应 Content-Type（如 application/javascript；默认 text/plain）"},
				"response_body":         map[string]any{"type": "string", "description": "HTTP 回调响应体（可选，至多 4KB，可放 stage-2 JS 载荷）"},
			},
		},
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: allow,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			if s.oob == nil {
				return actool.Errorf("oob 托管服务未启用"), nil
			}
			ri := agent.RunInfoFrom(ctx)
			if ri.TaskID <= 0 {
				return actool.Errorf("缺少任务上下文，拒绝分配 OOB 端点"), nil
			}
			var a struct {
				Label               string `json:"label"`
				TTLMinutes          int    `json:"ttl_minutes"`
				Driver              string `json:"driver"`
				StatusCode          int    `json:"status_code"`
				ResponseContentType string `json:"response_content_type"`
				ResponseBody        string `json:"response_body"`
			}
			_ = json.Unmarshal(in, &a)
			e, err := s.oob.Allocate(oob.AllocateOpts{
				TaskID:       strconv.FormatInt(ri.TaskID, 10),
				Label:        a.Label,
				TTL:          time.Duration(a.TTLMinutes) * time.Minute,
				Driver:       a.Driver,
				StatusCode:   a.StatusCode,
				ContentType:  a.ResponseContentType,
				ResponseBody: a.ResponseBody,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"token":      e.Token,
				"url":        e.URL,
				"path":       e.Path,
				"driver":     e.Driver,
				"expires_at": e.ExpiresAt.Format(time.RFC3339),
				"note":       "将该 URL（或按目标可达地址替换主机后的 URL）注入目标；随后用 oob_poll(token) 等待/读取回调证据，token 已跨单兵波次持久化。",
			})
		},
	})
}

func (s *Server) oobPollTool() actool.CoreTool {
	allow := func(context.Context, json.RawMessage, permission.Context) permission.Decision {
		return permission.Allowed()
	}
	return actool.Build(actool.Spec{
		Name: "oob_poll",
		Description: "查询或长轮询当前任务下托管 OOB 端点收到的回调事件（含 method / path / query / headers / body / remote_ip）。" +
			"不传 token 时列出本任务全部存活的 OOB 端点（便于跨波次单兵接力回收上轮回调）；传 token 时返回 since_seq 之后的新事件，可设 wait_seconds（0-30s）阻塞等待命中。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"token":        map[string]any{"type": "string", "description": "OOB 端点 token；省略时列出本任务全部活跃 OOB 端点"},
				"since_seq":    map[string]any{"type": "integer", "description": "仅返回 seq > since_seq 的新事件（默认 0）"},
				"wait_seconds": map[string]any{"type": "integer", "description": "无新事件时最多等待秒数（0-30，默认 0）"},
				"limit":        map[string]any{"type": "integer", "description": "最多返回事件条数（默认 50）"},
				"release":      map[string]any{"type": "boolean", "description": "true 时读取后顺带销毁该端点（仅在指定 token 时生效）"},
			},
		},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Permissions: allow,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			if s.oob == nil {
				return actool.Errorf("oob 托管服务未启用"), nil
			}
			ri := agent.RunInfoFrom(ctx)
			if ri.TaskID <= 0 {
				return actool.Errorf("缺少任务上下文，拒绝读取 OOB 端点"), nil
			}
			taskID := strconv.FormatInt(ri.TaskID, 10)
			var a struct {
				Token       string `json:"token"`
				SinceSeq    int64  `json:"since_seq"`
				WaitSeconds int    `json:"wait_seconds"`
				Limit       int    `json:"limit"`
				Release     bool   `json:"release"`
			}
			_ = json.Unmarshal(in, &a)
			tok := strings.TrimSpace(a.Token)
			if tok == "" {
				return jsonResult(map[string]any{
					"endpoints": s.oob.List(taskID),
				})
			}
			events, entry, err := s.oob.Poll(ctx, taskID, tok, a.SinceSeq, time.Duration(a.WaitSeconds)*time.Second, a.Limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if a.Release {
				s.oob.Delete(taskID, tok)
			}
			payload, err := json.Marshal(map[string]any{
				"token":        entry.Token,
				"label":        entry.Label,
				"hits":         entry.Hits,
				"next_seq":     entry.NextSeq,
				"interactions": events,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(agent.WrapUntrustedData("oob-callback", string(payload))), nil
		},
	})
}

func (s *Server) seedOOBTools() {
	if s.m == nil || s.m.PG() == nil {
		return
	}
	agents, _ := json.Marshal([]string{"worker", "pentest", "mainagent", "auto"})
	for _, t := range s.oobTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.PG().SeedTool(t.Name(), t.Description(), schema, agents); err != nil {
			log.Printf("[tools] seed %s 失败: %v", t.Name(), err)
		}
		s.syncBuiltinToolSchema(t.Name(), t.Description(), schema)
	}
}
