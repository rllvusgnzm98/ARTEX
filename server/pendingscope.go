// pendingscope.go：未授权网段登记(pending_scope)的发现侧挂钩与审批 API。
//
// 发现侧:session_recon 被动侦察落库后,对出当前 task_scope 的新 IP 按 /24 聚合
// 登记(upsert 幂等,重复侦察只累 hits 不刷屏),首次登记往任务活动流写通知卡。
// 审批侧:GET 列表 + POST decide;approve 把网段写进 task_scope(source='manual',
// kind=cidr),dismiss 只改状态。
package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
)

// scopeRulesFromRows 把官方 task_scope 行归一成 ScopeMatcher 规则。
// RoE 出界判定与 pending_scope 发现侧共用此函数。pending_scope 本身仍是
// 范围扩张队列,不是出界行动硬闸。
func scopeRulesFromRows(rows []db.TaskScope) []guard.ScopeRule {
	out := make([]guard.ScopeRule, 0, len(rows))
	for _, r := range rows {
		switch r.Kind {
		case "root_domain", "subdomain":
			if r.Domain != "" {
				out = append(out, guard.ScopeRule{Kind: "domain", Value: r.Domain})
			}
		case "ip", "cidr":
			if r.Net != "" {
				out = append(out, guard.ScopeRule{Kind: "cidr", Value: r.Net})
			}
		case "icp":
			if r.Value != "" {
				out = append(out, guard.ScopeRule{Kind: "icp", Value: r.Value})
			}
		}
	}
	return out
}

// cSegment24：IPv4 → /24,IPv6 → /48,非法 → ""。
func cSegment24(ipStr string) string {
	if ipStr == "" {
		return ""
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		parts := strings.Split(ipStr, ".")
		if len(parts) == 4 {
			return parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
		}
		return ""
	}
	_, ipnet, err := net.ParseCIDR(ipStr + "/48")
	if err != nil {
		return ""
	}
	return ipnet.String()
}

// reconRegisterPendingScope 对侦察新发现的 IP 逐个过当前任务 scope：
// ScopeOut 的按段聚合 UpsertPendingScope；首次登记写一张待授权通知卡。
// ScopeUnknown（任务无任何 scope 规则）时 Check 不会返回 ScopeOut，整批跳过。
func (s *Server) reconRegisterPendingScope(taskID int64, ips map[string]bool) {
	if s.m == nil {
		return
	}
	as := s.m.Assets()
	if as == nil || taskID <= 0 || len(ips) == 0 {
		return
	}
	rows, err := as.ListTaskScope(taskID)
	if err != nil {
		return
	}
	matcher := guard.NewScopeMatcher(scopeRulesFromRows(rows))
	segExample := map[string]string{}
	for ip := range ips {
		if matcher.Check(ip) != guard.ScopeOut {
			continue
		}
		if seg := cSegment24(ip); seg != "" {
			if _, ok := segExample[seg]; !ok {
				segExample[seg] = ip
			}
		}
	}
	for seg, exampleIP := range segExample {
		created, err := as.UpsertPendingScope(taskID, "cidr", seg)
		if err != nil {
			log.Printf("[pendingscope] 任务 %d 登记 %s 失败: %v", taskID, seg, err)
			continue
		}
		if created {
			s.notifyPendingScope(taskID, seg, exampleIP)
		}
	}
}

func (s *Server) notifyPendingScope(taskID int64, seg, exampleIP string) {
	if s.m == nil || s.engine == nil {
		return
	}
	t, ok := s.m.Task(strconv.FormatInt(taskID, 10))
	if !ok {
		return
	}
	detail, _ := json.Marshal(map[string]any{
		"cidr": seg, "example_ip": exampleIP,
		"list_api": fmt.Sprintf("/api/tasks/%d/pending-scope", taskID),
	})
	s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
		Summary: fmt.Sprintf("发现未授权网段 %s(示例 IP %s),已登记待授权;人工批准后才扩 scope", seg, exampleIP),
		Detail:  string(detail)})
}

// GET /api/tasks/{id}/pending-scope — 待授权网段列表(默认只 pending,?all=1 含已决)。
func (s *Server) pendingScopeList(w http.ResponseWriter, r *http.Request) {
	if s.m == nil {
		writeErr(w, 503, "asset store 未启用")
		return
	}
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	as := s.m.Assets()
	if as == nil {
		writeErr(w, 503, "asset store 未启用")
		return
	}
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	items, err := as.ListPendingScope(taskID, r.URL.Query().Get("all") == "1")
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

// POST /api/pending-scope/{id}/decide {action:"approve"|"dismiss"}
// approve 先把网段写进 task_scope(kind=cidr,source='manual')再迁移状态;dismiss 只迁移状态。
func (s *Server) pendingScopeDecide(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.Assets() == nil {
		writeErr(w, 503, "asset store 未启用")
		return
	}
	as := s.m.Assets()
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	var body struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	approve := body.Action == "approve"
	if body.Action != "approve" && body.Action != "dismiss" {
		writeErr(w, 400, "action 必须是 approve 或 dismiss")
		return
	}
	row, err := as.GetPendingScope(id)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, "pending_scope 条目不存在")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	desired := "dismissed"
	if approve {
		desired = "approved"
	}
	if row.Status != "pending" {
		if row.Status == desired {
			writeJSON(w, 200, row)
			return
		}
		writeErr(w, 409, "条目已处置(status="+row.Status+"),冲突决定不予受理")
		return
	}
	if approve {
		if _, err := as.AddAgentScope(row.TaskID, row.Kind, row.Value,
			fmt.Sprintf("人工批准扩 scope(pending_scope #%d)", row.ID), "manual"); err != nil {
			writeErr(w, 400, "写入 task_scope 失败: "+err.Error())
			return
		}
	}
	row, err = as.DecidePendingScope(id, approve)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, row)
}
