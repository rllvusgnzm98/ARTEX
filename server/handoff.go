// handoff.go：外网→内网任务移交。以一个立足点会话为起点建子任务：
// 初始官方 task_scope 只登记立足点主机 /32（source='manual'），只读继承原任务、
// parent_ref 父子关联。新网段写入 pending_scope（官方 scope 的扩容队列，
// 不是出界行动硬闸）。被动优先。
package server

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// handoffHostIP 确定立足点主机 IP：优先 host_asset_id 指向的资产，
// 回落会话 URL 的 IP 字面量 host。两者都没有 → ""。
func (s *Server) handoffHostIP(rec *db.SessionRecord) string {
	if rec.HostAssetID > 0 && s.m != nil && s.m.Assets() != nil {
		if assets, err := s.m.Assets().GetByIDs([]int64{rec.HostAssetID}); err == nil {
			for _, a := range assets {
				if a.IP != "" {
					return a.IP
				}
			}
		}
	}
	if u, err := url.Parse(rec.URL); err == nil {
		if h := u.Hostname(); net.ParseIP(h) != nil {
			return h
		}
	}
	return ""
}

// footholdSegment 把立足点 IP 聚成待扩容网段（IPv4 /24，IPv6 /48）。
func footholdSegment(ip string) string {
	if ip == "" {
		return ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	if parsed.To4() != nil {
		parts := strings.Split(ip, ".")
		if len(parts) == 4 {
			return parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
		}
		return ""
	}
	_, ipnet, err := net.ParseCIDR(ip + "/48")
	if err != nil {
		return ""
	}
	return ipnet.String()
}

// handoffGoal 构造移交 goal 文本：立足点信息 + pending 扩容队列 + 已授权 scope 背景 + 纪律。
func handoffGoal(rec *db.SessionRecord, hostIP string, pending []db.PendingScope, scope []db.TaskScope) string {
	var b strings.Builder
	fmt.Fprintf(&b, "内网横向:以会话 #%d(%s,%s)所在的立足点主机 %s 为起点,向内网纵深拓展。\n",
		rec.ID, rec.Kind, rec.URL, hostIP)
	fmt.Fprintf(&b, "立足点:session_id=%d kind=%s url=%s host_asset_id=%d。\n",
		rec.ID, rec.Kind, rec.URL, rec.HostAssetID)
	if len(pending) > 0 {
		segs := make([]string, 0, len(pending))
		for _, p := range pending {
			segs = append(segs, p.Value)
		}
		fmt.Fprintf(&b, "原任务已发现、待写入官方 task_scope 的网段（pending_scope 是扩容队列，不是出界行动硬闸）:%s。\n", strings.Join(segs, "、"))
	}
	if len(scope) > 0 {
		items := make([]string, 0, len(scope))
		for _, sc := range scope {
			v := sc.Domain + sc.Net + sc.Value
			if v != "" {
				items = append(items, fmt.Sprintf("%s=%s", sc.Kind, v))
			}
		}
		if len(items) > 0 {
			fmt.Fprintf(&b, "原任务已授权 scope(仅背景参考,不自动继承授权):%s。\n", strings.Join(items, "、"))
		}
	}
	b.WriteString("\n纪律:\n")
	b.WriteString("1. 本任务初始官方 scope 只有立足点主机 " + hostIP + "/32。被动侦察发现的新网段登记到 pending_scope，经批准后写入 task_scope 扩范围；pending_scope 是扩容队列，不是出界行动硬闸。\n")
	b.WriteString("2. 被动优先:先用 session_recon 只读命令拿网卡/路由/邻居/监听，信息不够再考虑主动探测。\n")
	b.WriteString("3. 需要出立足点的网络访问走已有隧道工具，不要在立足点外盲目扫描。\n")
	b.WriteString("4. 动静控制:经会话的命令注意留痕，避免大批量高噪声动作。\n")
	return b.String()
}

// applyHandoffScope 给子任务登记立足点 /32 官方 scope，并把新网段（含来源任务
// 仍 pending 的条目，以及立足点所在 /24 或 /48）写入子任务 pending_scope。
func applyHandoffScope(as *db.AssetStore, childID, sessionID int64, hostIP string, parentPending []db.PendingScope) error {
	if as == nil {
		return fmt.Errorf("asset store 未启用")
	}
	if _, err := as.AddAgentScope(childID, "ip", hostIP,
		fmt.Sprintf("handoff 立足点(session #%d)", sessionID), "manual"); err != nil {
		return fmt.Errorf("登记立足点 scope 失败: %w", err)
	}
	hostCIDR := hostIP + "/32"
	if p := net.ParseIP(hostIP); p != nil && p.To4() == nil {
		hostCIDR = hostIP + "/128"
	}
	seen := map[string]bool{hostCIDR: true}
	if seg := footholdSegment(hostIP); seg != "" && !seen[seg] {
		if _, err := as.UpsertPendingScope(childID, "cidr", seg); err != nil {
			return err
		}
		seen[seg] = true
	}
	for _, p := range parentPending {
		if p.Kind == "" || p.Value == "" || seen[p.Value] {
			continue
		}
		if _, err := as.UpsertPendingScope(childID, p.Kind, p.Value); err != nil {
			return err
		}
		seen[p.Value] = true
	}
	return nil
}

// POST /api/sessions/{id}/handoff — 外网→内网任务移交。
// 返回 {task_id, credentials_inherited}。凭据继承失败只记日志，不改变移交结果。
func (s *Server) sessionHandoff(w http.ResponseWriter, r *http.Request) {
	if !s.intranetSessionsReady(w) {
		return
	}
	if s.m == nil {
		writeErr(w, 503, "任务管理器未就绪")
		return
	}
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	rec, err := s.sessStore.Get(r.Context(), id)
	if err != nil {
		writeErr(w, 500, "会话读取失败: "+err.Error())
		return
	}
	if rec == nil {
		writeErr(w, 404, fmt.Sprintf("会话 %d 不存在", id))
		return
	}
	srcTask, ok := s.m.Task(strconv.FormatInt(rec.CreatedByTask, 10))
	if rec.CreatedByTask <= 0 || !ok {
		writeErr(w, 404, fmt.Sprintf("会话 %d 的来源任务 #%d 不存在", id, rec.CreatedByTask))
		return
	}
	hostIP := s.handoffHostIP(rec)
	if hostIP == "" {
		writeErr(w, 400, "无法确定立足点主机 IP(host_asset 无 IP 且会话 URL 非 IP 字面量)")
		return
	}
	as := s.m.Assets()
	if as == nil {
		writeErr(w, 503, "asset store 未启用")
		return
	}
	pending, err := as.ListPendingScope(rec.CreatedByTask, false)
	if err != nil {
		writeErr(w, 500, "pending_scope 读取失败: "+err.Error())
		return
	}
	scope, err := as.ListTaskScope(rec.CreatedByTask)
	if err != nil {
		writeErr(w, 500, "task_scope 读取失败: "+err.Error())
		return
	}

	desc := fmt.Sprintf("内网横向(立足点会话 #%d %s)", rec.ID, hostIP)
	goal := handoffGoal(rec, hostIP, pending, scope)
	t, err := s.m.CreateTaskWithOptions(desc, goal, db.TaskCreateOptions{
		SourceTaskIDs: []int64{rec.CreatedByTask},
	})
	if err != nil {
		writeErr(w, 500, "建子任务失败: "+err.Error())
		return
	}
	t.ParentRef = srcTask.ID
	newID, e := strconv.ParseInt(t.ID, 10, 64)
	if e != nil {
		writeErr(w, 500, "子任务 id 非法: "+t.ID)
		return
	}
	_ = s.m.PG().SetParentRef(newID, srcTask.ID)
	if err := applyHandoffScope(as, newID, rec.ID, hostIP, pending); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	inherited, ierr := s.inheritCredentials(rec.CreatedByTask, newID)
	if ierr != nil {
		log.Printf("[handoff] inherit credentials parent=%d child=%d: %v", rec.CreatedByTask, newID, ierr)
	}
	// 测试夹具可不装配 engine；有引擎时再走与 spawn_task 相同的建后流程。
	if s.engine != nil {
		s.launchTask(t, desc+" "+goal, false)
	}
	s.auditIntranet(r, "handoff session=%d host=%s → task=%s(来源任务 %s)", rec.ID, hostIP, t.ID, srcTask.ID)
	writeJSON(w, 200, map[string]any{
		"task_id":               t.ID,
		"credentials_inherited": inherited,
	})
}
