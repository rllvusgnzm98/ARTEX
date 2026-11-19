package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
)

// settingRoEEnforcement 是 RoE 三态设置键:"off" | "warn"(默认) | "strict"。
// 空值与未知值由 guard.RoEConfig.mode 回落为 warn。
const settingRoEEnforcement = "roe_enforcement"

// newRoEConfig 把 settings 里的 roe_enforcement 与 task_scope(官方范围,不含
// pending_scope)接到 guard。Scope 每次现读,不缓存,add_task_scope 即时生效。
// pending_scope 只是范围扩张队列,不是出界行动硬闸。
func newRoEConfig(pg *db.DB) guard.RoEConfig {
	if pg == nil {
		return guard.RoEConfig{}
	}
	return guard.RoEConfig{
		Mode: func() string {
			v, _, _ := pg.GetSetting(settingRoEEnforcement)
			return v
		},
		Scope: func(taskID int64) ([]guard.ScopeRule, error) {
			rows, err := pg.Assets().ListTaskScope(taskID)
			if err != nil {
				return nil, err // 读失败交给 guard:strict 不得当成空范围放行
			}
			return scopeRulesFromRows(rows), nil
		},
		TaskIDOf: func(ctx context.Context) int64 {
			return agent.RunInfoFrom(ctx).TaskID
		},
	}
}

// scopeRulesFromRows 定义见 pendingscope.go:官方 task_scope 归一,RoE 与
// pending_scope 发现侧共用。pending_scope 仍只是范围扩张队列,不是出界行动硬闸。

// sessionRoECheck 在登记会话前校验目标 URL 的 host 是否在本任务官方范围内:
// strict 拦截、warn 告警放行、范围未登记/范围内直接放行。非任务运行按未登记放行。
func (s *Server) sessionRoECheck(ctx context.Context, rawURL string) (string, error) {
	return s.roeCheckHost(ctx, hostFromURL(rawURL), "立足点目标")
}

// roeCheckHost 与 register_session / tunnel_deploy 共用:strict 拦截、warn 告警放行、fail-open。
func (s *Server) roeCheckHost(ctx context.Context, host, kind string) (string, error) {
	ri := agent.RunInfoFrom(ctx)
	if ri.TaskID <= 0 || s.m == nil || s.m.pg == nil || strings.TrimSpace(host) == "" {
		return "", nil
	}
	mode, _, _ := s.m.pg.GetSetting(settingRoEEnforcement)
	if strings.EqualFold(strings.TrimSpace(mode), "off") {
		return "", nil
	}
	rows, err := s.m.pg.Assets().ListTaskScope(ri.TaskID)
	if err != nil {
		return "", nil
	}
	verdict := guard.NewScopeMatcher(scopeRulesFromRows(rows)).Check(host)
	if verdict != guard.ScopeOut {
		return "", nil
	}
	msg := fmt.Sprintf("RoE 授权范围检查：%s %s 不在本任务(task %d)已登记范围内。"+
		"如需放行：把目标加入任务范围(add_task_scope)，或在系统设置把 roe_enforcement 改为 warn/off。",
		kind, host, ri.TaskID)
	if strings.EqualFold(strings.TrimSpace(mode), "strict") {
		return "", fmt.Errorf("%s", msg)
	}
	return "⚠ " + msg, nil
}

func hostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// guardAutoAllowGet 返回当前一键放行状态(含剩余秒数)。到期在读取时惰性关闭。
func (s *Server) guardAutoAllowGet(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.interceptor == nil {
		writeJSON(w, 200, map[string]any{"enabled": false, "expires_at": 0, "remaining_seconds": 0})
		return
	}
	writeJSON(w, 200, s.m.interceptor.AutoAllowStatus())
}

// guardAutoAllowSet 开启/关闭一键放行。开启时 hours 夹逼到 {2,4,8};关闭时忽略 hours。
// 只自动放行 ask;deny 不走这条路径。
func (s *Server) guardAutoAllowSet(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.interceptor == nil {
		writeErr(w, 500, "拦截器未就绪")
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
		Hours   int  `json:"hours"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := s.m.interceptor.SetAutoAllow(req.Enabled, req.Hours); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, s.m.interceptor.AutoAllowStatus())
}
