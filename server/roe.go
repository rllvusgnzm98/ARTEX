package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
)

// localRoEExemptHosts collects local/VPN interface IPs (net.InterfaceAddrs)
// plus platform callback / own-infra hosts (ARTEX_CALLBACK_ADDR, callback_addr,
// own_infra_hosts) so operator/attacker local interfaces never spam RoE alerts.
func localRoEExemptHosts() []string {
	return guard.LocalExemptHosts(config.OwnInfraHosts()...)
}

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
			modeVal, _, _ := pg.GetSetting(settingRoEEnforcement)
			return scopeRulesFromRowsForMode(rows, modeVal), nil
		},
		TaskIDOf: func(ctx context.Context) int64 {
			return agent.RunInfoFrom(ctx).TaskID
		},
		ExemptHosts: localRoEExemptHosts,
	}
}

// scopeRulesFromRows 定义见 pendingscope.go:官方 task_scope 归一,RoE 与
// pending_scope 发现侧共用。pending_scope 仍只是范围扩张队列,不是出界行动硬闸。

// loadTaskScopeRows 是 RoE 的范围读取点。生产路径走 AssetStore.ListTaskScope。
// 测试可替换它，单独模拟读失败，同时让 roe_enforcement 仍从库里读到。
var loadTaskScopeRows = func(pg *db.DB, taskID int64) ([]db.TaskScope, error) {
	if pg == nil {
		return nil, fmt.Errorf("范围存储未就绪")
	}
	return pg.Assets().ListTaskScope(taskID)
}

// normalizeRoEMode 把设置值收成 off|warn|strict。空值与未知值回落 warn。
func normalizeRoEMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "off":
		return "off"
	case "strict":
		return "strict"
	default:
		return "warn"
	}
}

func (s *Server) roeMode() string {
	if s == nil || s.m == nil || s.m.pg == nil {
		return "warn"
	}
	raw, _, _ := s.m.pg.GetSetting(settingRoEEnforcement)
	return normalizeRoEMode(raw)
}

// roeVerdictFor 是会话、隧道与任务代理共用的范围判定内核。
// off 直接 ScopeUnknown；taskID<=0 或 host 为空也是 ScopeUnknown 且 err==nil；
// ListTaskScope 失败返回 ScopeUnknown 与 err，由调用方按 strict/warn 决定。
func (s *Server) roeVerdictFor(taskID int64, host string) (guard.ScopeVerdict, string, error) {
	mode := s.roeMode()
	if mode == "off" {
		return guard.ScopeUnknown, mode, nil
	}
	if taskID <= 0 || strings.TrimSpace(host) == "" {
		return guard.ScopeUnknown, mode, nil
	}
	if s == nil || s.m == nil || s.m.pg == nil {
		return guard.ScopeUnknown, mode, fmt.Errorf("范围存储未就绪")
	}
	rows, err := loadTaskScopeRows(s.m.pg, taskID)
	if err != nil {
		return guard.ScopeUnknown, mode, err
	}
	matcher := guard.NewScopeMatcher(scopeRulesFromRowsForMode(rows, mode))
	matcher.AddExemptHosts(localRoEExemptHosts())
	return matcher.Check(host), mode, nil
}

// sessionRoECheck 在登记会话前校验目标 URL 的 host 是否在本任务官方范围内:
// strict 拦截、warn 告警放行、范围未登记/范围内直接放行。非任务运行按未登记放行。
func (s *Server) sessionRoECheck(ctx context.Context, rawURL string) (string, error) {
	return s.roeCheckHost(ctx, hostFromURL(rawURL), "立足点目标")
}

// roeCheckHost 与 register_session / tunnel_deploy 共用。
// strict 拦截（含范围读失败，不得 fail-open），warn 告警放行，off 放行。
// 非任务运行（TaskID<=0）与存储未就绪保持放行。面向调用方的错误不含 DSN。
func (s *Server) roeCheckHost(ctx context.Context, host, kind string) (string, error) {
	ri := agent.RunInfoFrom(ctx)
	if ri.TaskID <= 0 || s.m == nil || s.m.pg == nil || strings.TrimSpace(host) == "" {
		return "", nil
	}
	verdict, mode, err := s.roeVerdictFor(ri.TaskID, host)
	if mode == "off" {
		return "", nil
	}
	if err != nil {
		log.Printf("[roe] task %d 范围读取失败(mode=%s): %v", ri.TaskID, mode, err)
		if mode == "strict" {
			return "", fmt.Errorf("RoE 授权范围检查：%s %s 范围读取失败，strict 拒绝放行（非未登记范围）。可改用 warn/off 回退。", kind, host)
		}
		return "⚠ RoE 授权范围检查：范围读取失败，warn 下放行（非未登记范围）。", nil
	}
	if verdict != guard.ScopeOut {
		return "", nil
	}
	msg := fmt.Sprintf("RoE 授权范围检查：%s %s 不在本任务(task %d)已登记范围内。"+
		"如需放行：把目标加入任务范围(add_task_scope)，或在系统设置把 roe_enforcement 改为 warn/off。",
		kind, host, ri.TaskID)
	if mode == "strict" {
		return "", fmt.Errorf("%s", msg)
	}
	warn := "⚠ " + msg
	// 后续探针/部署可能失败，到那时调用方拿不到这个返回值。先留痕。
	s.recordRoEWarn(ri.TaskID, host, warn)
	return warn, nil
}

// recordRoEWarn 沿用 recordProxyRoEWarn：先打结构化日志，任务句柄还在时再写
// activity。没有句柄（或 Store 为空）时日志仍然留下，不改调用方拿到的 ⚠ 文案。
func (s *Server) recordRoEWarn(taskID int64, host, msg string) {
	log.Printf("[roe] task %d host %s: %s", taskID, host, msg)
	if s == nil || s.m == nil {
		return
	}
	t, ok := s.m.Task(strconv.FormatInt(taskID, 10))
	if !ok || t == nil || t.Store == nil {
		return
	}
	if _, err := t.Store.AppendActivity(db.Activity{
		Worker: "system", Kind: "text", Tool: "roe",
		Summary: msg, Detail: msg,
	}); err != nil {
		log.Printf("[roe] activity 写入失败 task %d: %v", taskID, err)
	}
}

// withRoEWarn 把 warn 越界文案留在后续失败的结果里。warn 为空时原样返回，
// strict/off 以及范围内放行的错误文案不变。
func withRoEWarn(warn, msg string) string {
	if warn == "" {
		return msg
	}
	return warn + "\n" + msg
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
