// intranet.go 是内网页的人工操作 API：会话台账、探活、目录列举与读写、只读拓扑。
// 全部挂在 /api 下 requireAuth 之后(JWT)。本刀不包含隧道、凭据、移交。
package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/session"
	"github.com/golang-jwt/jwt/v5"
)

// auditIntranet 打人工操作审计日志:操作者(JWT subject)/来源地址/动作明细。
// 人工 exec/write/teardown/delete 必走这里;失败也记(结果含在明细里)。
// operatorName 从当前请求的 JWT 取 subject。有钥匙环时按 kid 选键，轮换后的令牌仍能记操作者。
func (s *Server) operatorName(r *http.Request) string {
	if s != nil && s.useKeyRing() {
		claims, ok := s.jwtRing.verify(extractToken(r))
		if !ok || claims == nil || claims.Subject == "" {
			return "unknown"
		}
		return claims.Subject
	}
	var key []byte
	if s != nil {
		key = s.jwtKey
	}
	return intranetOperator(r, key)
}

func intranetOperator(r *http.Request, key []byte) string {
	tok := extractToken(r)
	if tok == "" || len(key) == 0 {
		return "unknown"
	}
	claims := jwt.RegisteredClaims{}
	t, err := jwt.ParseWithClaims(tok, &claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return key, nil
	})
	if err != nil || t == nil || !t.Valid || claims.Subject == "" {
		return "unknown"
	}
	return claims.Subject
}

func (s *Server) auditIntranet(r *http.Request, format string, args ...any) {
	op := s.operatorName(r)
	log.Printf("[intranet] op=%s remote=%s %s", op, r.RemoteAddr, fmt.Sprintf(format, args...))
}

// intranetSessionsReady 是路由级前置:会话子系统(DB/注册表)未就绪时写 503。
func (s *Server) intranetSessionsReady(w http.ResponseWriter) bool {
	if s.sessStore == nil || s.sessReg == nil {
		writeErr(w, 503, "会话子系统未就绪(DB 未连接)")
		return false
	}
	return true
}

func pathID(r *http.Request, name string) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("非法 %s: %q", name, r.PathValue(name))
	}
	return id, nil
}

// sessionItem 是台账行的 Web 投影:不含 secret(连接密码/加密密钥不出 server)。
func sessionItem(rec *db.SessionRecord) map[string]any {
	item := map[string]any{
		"id": rec.ID, "kind": rec.Kind, "url": rec.URL, "lang": rec.Lang,
		"host_asset_id": rec.HostAssetID, "status": rec.Status,
		"last_beat": rec.LastBeat, "created_at": rec.CreatedAt,
		"created_by_task": rec.CreatedByTask, "created_by_intent": rec.CreatedByIntent,
	}
	// platform 在 secret JSON 里(探测指纹);解析失败只缺字段,不影响列表。
	var sec session.Secret
	if err := json.Unmarshal(rec.Secret, &sec); err == nil && sec.Platform != "" {
		item["platform"] = sec.Platform
	}
	return item
}

// GET /api/sessions?task_id= — 会话台账全量(含 dead,前端自行过滤);
// 传 task_id 时只留本任务创建的会话(与拓扑同口径),不传保持全局视图。
func (s *Server) intranetListSessions(w http.ResponseWriter, r *http.Request) {
	if !s.intranetSessionsReady(w) {
		return
	}
	taskID, ok := parseTaskIDQuery(w, r)
	if !ok {
		return
	}
	recs, err := s.sessStore.List(r.Context(), "")
	if err != nil {
		writeErr(w, 500, "会话台账读取失败: "+err.Error())
		return
	}
	if taskID > 0 {
		filtered := recs[:0]
		for _, rec := range recs {
			if rec.CreatedByTask == taskID {
				filtered = append(filtered, rec)
			}
		}
		recs = filtered
	}
	items := []map[string]any{}
	for _, rec := range recs {
		items = append(items, sessionItem(rec))
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

// GET /api/sessions/{id} — 单条详情。
func (s *Server) intranetGetSession(w http.ResponseWriter, r *http.Request) {
	if !s.intranetSessionsReady(w) {
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
	writeJSON(w, 200, sessionItem(rec))
}

// lookupLiveSession 取注册表活会话;查无/已死返回带语义错误(人工通道文案)。
func (s *Server) lookupLiveSession(id int64) (session.Session, error) {
	sess, ok := s.sessReg.Get(id)
	if !ok {
		return nil, fmt.Errorf("会话 %d 不在注册表(未登记/已删除/进程重启后恢复失败)", id)
	}
	return sess, nil
}

// POST /api/sessions/{id}/exec {command, timeout?} → {stdout,stderr,ms,timed_out}。
// 人工执行:审计日志必记(操作者/会话/命令/耗时/结果)。
func (s *Server) intranetExec(w http.ResponseWriter, r *http.Request) {
	if !s.intranetSessionsReady(w) {
		return
	}
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	var a struct {
		Command string `json:"command"`
		Timeout int    `json:"timeout"`
	}
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
		writeErr(w, 400, "请求体 JSON 解析失败: "+err.Error())
		return
	}
	a.Command = strings.TrimSpace(a.Command)
	if a.Command == "" {
		writeErr(w, 400, "command 必填")
		return
	}
	if a.Timeout <= 0 {
		a.Timeout = 15
	}
	if a.Timeout > 300 {
		a.Timeout = 300 // 人工通道上限,防页面挂死长命令
	}
	sess, err := s.lookupLiveSession(id)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	start := time.Now()
	stdout, stderr, execErr := sess.Exec(r.Context(), a.Command, time.Duration(a.Timeout)*time.Second)
	ms := time.Since(start).Milliseconds()
	s.sessStore.Touch(r.Context(), id)
	// 驱动内部用 context.WithTimeout 实现超时,错误文本含 "deadline exceeded"。
	timedOut := execErr != nil && (errors.Is(r.Context().Err(), context.DeadlineExceeded) ||
		strings.Contains(execErr.Error(), "deadline exceeded"))
	if execErr != nil && !timedOut {
		s.auditIntranet(r, "exec session=%d cmd=%q ms=%d 失败: %v", id, a.Command, ms, execErr)
		writeErr(w, 502, "执行失败: "+execErr.Error())
		return
	}
	s.auditIntranet(r, "exec session=%d cmd=%q ms=%d timed_out=%v stdout=%dB",
		id, a.Command, ms, timedOut, len(stdout))
	out := map[string]any{
		"stdout": truncateOutput(stdout), "stderr": truncateOutput(stderr),
		"ms": ms, "timed_out": timedOut,
	}
	if timedOut {
		out["error"] = "执行超时: " + execErr.Error()
	}
	if len(stdout) > maxSessionToolOutput || len(stderr) > maxSessionToolOutput {
		out["truncated"] = true
	}
	writeJSON(w, 200, out)
}

// sessionProbeTimeout 是人工探活(Test 探针)的统一超时。
const sessionProbeTimeout = 10 * time.Second

// POST /api/sessions/{id}/probe — 人工触发探活:对会话执行无害 Test() 探针
// (10s 超时)。成功 → status=alive + 刷新 last_beat;失败 → 诚实标 dead
// (治理「靶场已停、台账仍显示存活」的假存活)。返回 {alive, ms, error?}。
func (s *Server) intranetProbeSession(w http.ResponseWriter, r *http.Request) {
	if !s.intranetSessionsReady(w) {
		return
	}
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	sess, err := s.lookupLiveSession(id)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), sessionProbeTimeout)
	defer cancel()
	start := time.Now()
	probeErr := sess.Test(ctx)
	ms := time.Since(start).Milliseconds()
	if probeErr != nil {
		// 标 dead 用独立短 ctx:探活 ctx 可能已随超时取消,标死必须落库。
		dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
		uerr := s.sessStore.UpdateStatus(dctx, id, db.SessionDead)
		dcancel()
		if uerr != nil {
			writeErr(w, 500, "探活失败且状态落库失败: "+uerr.Error())
			return
		}
		s.auditIntranet(r, "probe session=%d ms=%d dead: %v", id, ms, probeErr)
		writeJSON(w, 200, map[string]any{"alive": false, "ms": ms, "error": probeErr.Error()})
		return
	}
	// 探活成功:状态归 alive(可从 dead 复活)并刷新心跳。
	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	uerr := s.sessStore.UpdateStatus(dctx, id, db.SessionAlive)
	dcancel()
	if uerr != nil {
		writeErr(w, 500, "状态落库失败: "+uerr.Error())
		return
	}
	s.sessStore.Touch(r.Context(), id)
	s.auditIntranet(r, "probe session=%d ms=%d alive", id, ms)
	writeJSON(w, 200, map[string]any{"alive": true, "ms": ms})
}

// shellQuote 复用 customtool.go 的同款实现(单引号包裹,' → '\'')。

type dirEntry struct {
	Name  string `json:"name"`
	IsDir bool   `json:"is_dir"`
	Size  int64  `json:"size"`
}

// parseLsLa 把 `ls -la` 输出解析为条目列表(纯函数,可测)。
// 跳过 total 行、. / ..、无法识别的行;symlink 的 "name -> target" 只留 name。
func parseLsLa(out string) []dirEntry {
	entries := []dirEntry{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "total ") {
			continue
		}
		fields := strings.Fields(line)
		// perms links owner group size mon day time/year name...
		if len(fields) < 9 {
			continue
		}
		perms := fields[0]
		if len(perms) != 10 || !strings.ContainsRune("-dlbcps", rune(perms[0])) {
			continue
		}
		size, err := strconv.ParseInt(fields[4], 10, 64)
		if err != nil {
			continue
		}
		name := strings.Join(fields[8:], " ")
		if i := strings.Index(name, " -> "); perms[0] == 'l' && i >= 0 {
			name = name[:i]
		}
		if name == "." || name == ".." || name == "" {
			continue
		}
		entries = append(entries, dirEntry{Name: name, IsDir: perms[0] == 'd', Size: size})
	}
	return entries
}

// POST /api/sessions/{id}/list {path} → {entries:[{name,is_dir,size}]}。
// 驱动无 ListDir 抽象,统一走 `ls -la` 经 Exec 解析(Windows 马会报驱动错误)。
func (s *Server) intranetListDir(w http.ResponseWriter, r *http.Request) {
	if !s.intranetSessionsReady(w) {
		return
	}
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	var a struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
		writeErr(w, 400, "请求体 JSON 解析失败: "+err.Error())
		return
	}
	a.Path = strings.TrimSpace(a.Path)
	if a.Path == "" {
		writeErr(w, 400, "path 必填")
		return
	}
	sess, err := s.lookupLiveSession(id)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	stdout, _, err := sess.Exec(r.Context(), "ls -la "+shellQuote(a.Path), 15*time.Second)
	s.sessStore.Touch(r.Context(), id)
	if err != nil {
		writeErr(w, 502, "列目录失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"entries": parseLsLa(stdout)})
}

// POST /api/sessions/{id}/read {path} → {content?|content_base64?, truncated}。
func (s *Server) intranetReadFile(w http.ResponseWriter, r *http.Request) {
	if !s.intranetSessionsReady(w) {
		return
	}
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	var a struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
		writeErr(w, 400, "请求体 JSON 解析失败: "+err.Error())
		return
	}
	a.Path = strings.TrimSpace(a.Path)
	if a.Path == "" {
		writeErr(w, 400, "path 必填")
		return
	}
	sess, err := s.lookupLiveSession(id)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	data, err := sess.ReadFile(r.Context(), a.Path)
	s.sessStore.Touch(r.Context(), id)
	if err != nil {
		writeErr(w, 502, "读取失败: "+err.Error())
		return
	}
	s.auditIntranet(r, "read session=%d path=%q size=%dB", id, a.Path, len(data))
	out := map[string]any{"size": len(data)}
	truncated := false
	if len(data) > maxSessionToolOutput {
		data = data[:maxSessionToolOutput]
		truncated = true
	}
	if utf8.Valid(data) {
		out["content"] = string(data)
	} else {
		out["content_base64"] = base64.StdEncoding.EncodeToString(data)
	}
	if truncated {
		out["truncated"] = true
	}
	writeJSON(w, 200, out)
}

// POST /api/sessions/{id}/write {path, content_base64} → {ok, bytes}。
// 高危写操作:无论成败都记审计日志。
func (s *Server) intranetWriteFile(w http.ResponseWriter, r *http.Request) {
	if !s.intranetSessionsReady(w) {
		return
	}
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	var a struct {
		Path          string `json:"path"`
		ContentBase64 string `json:"content_base64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
		writeErr(w, 400, "请求体 JSON 解析失败: "+err.Error())
		return
	}
	a.Path = strings.TrimSpace(a.Path)
	if a.Path == "" {
		writeErr(w, 400, "path 必填")
		return
	}
	data, err := base64.StdEncoding.DecodeString(a.ContentBase64)
	if err != nil {
		writeErr(w, 400, "content_base64 解码失败: "+err.Error())
		return
	}
	sess, err := s.lookupLiveSession(id)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	if err := sess.WriteFile(r.Context(), a.Path, data); err != nil {
		s.auditIntranet(r, "write session=%d path=%q bytes=%d 失败: %v", id, a.Path, len(data), err)
		writeErr(w, 502, "写入失败: "+err.Error())
		return
	}
	s.sessStore.Touch(r.Context(), id)
	s.auditIntranet(r, "write session=%d path=%q bytes=%d 成功", id, a.Path, len(data))
	writeJSON(w, 200, map[string]any{"ok": true, "bytes": len(data)})
}

// DELETE /api/sessions/{id} — 关闭并从注册表/DB 移除(幂等:已不存在也 ok)。
func (s *Server) intranetDeleteSession(w http.ResponseWriter, r *http.Request) {
	if !s.intranetSessionsReady(w) {
		return
	}
	id, err := pathID(r, "id")
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	inReg := s.sessReg.Remove(id) // Remove 内部关闭会话
	if err := s.sessStore.Delete(r.Context(), id); err != nil {
		writeErr(w, 500, "会话删除失败: "+err.Error())
		return
	}
	s.auditIntranet(r, "delete session=%d in_registry=%v", id, inReg)
	writeJSON(w, 200, map[string]any{"ok": true, "id": id, "was_live": inReg})
}

// GET /api/tunnels?task_id= 由 intranetListTunnels 实现（本刀已接线）。
// legacy stub:
// GET /api/tunnels?task_id= — 台账全量(含 stopped,全字段);
// 传 task_id 时只留本任务的隧道,不传保持全局视图(兼容旧前端)。
// 注意:deploy_params 含隧道 auth token(平台自造一次性令牌),仅 JWT 后可见。

// topoTunnel 是拓扑组装可选的隧道边。台账未就绪或查找失败时调用方传 nil。
type topoTunnel struct {
	ID           int64
	Kind         string
	TargetHost   string
	TargetPort   int
	ViaSessionID int64
	State        string
}

type topoNode struct {
	ID            string           `json:"id"` // asset-<id> | sess-<sessionID> | pf-<id> | platform
	IP            string           `json:"ip"`
	Segment       string           `json:"segment"`
	HasSession    bool             `json:"has_session"`
	AliveSessions int              `json:"alive_sessions"`
	Services      []map[string]any `json:"services"`
	IsCallback    bool             `json:"is_callback"`
}

type topoEdge struct {
	ID    int64  `json:"id"`
	Kind  string `json:"kind"`
	From  string `json:"from"`
	To    string `json:"to"`
	State string `json:"state"`
}

type topoSegment struct {
	Name     string `json:"name"`
	ColorKey string `json:"color_key"`
}

func segmentOf(ip, cSegment string) string {
	if cSegment != "" {
		return cSegment
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	if v4 := parsed.To4(); v4 != nil {
		return (&net.IPNet{IP: v4.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}).String()
	}
	return (&net.IPNet{IP: parsed.Mask(net.CIDRMask(48, 128)), Mask: net.CIDRMask(48, 128)}).String()
}

// buildTopology 纯组装:ip 资产 + 会话主机去重为 nodes。tunnels 为追加边，不得丢掉资产或会话。
func buildTopology(assets []*db.Asset, recs []*db.SessionRecord, tunnels []topoTunnel, callbackHost string) map[string]any {
	nodes := map[string]*topoNode{}
	for _, a := range assets {
		if a == nil || a.IP == "" {
			continue
		}
		n := nodes[a.IP]
		if n == nil {
			n = &topoNode{ID: fmt.Sprintf("asset-%d", a.ID), IP: a.IP, Services: []map[string]any{}}
			nodes[a.IP] = n
		}
		for _, p := range a.OpenPorts {
			if port, ok := p["port"].(float64); ok && port > 0 {
				svc := map[string]any{"port": int(port)}
				if s, ok := p["service"].(string); ok && s != "" {
					svc["service"] = s
				}
				n.Services = append(n.Services, svc)
			}
		}
	}
	assetIP := map[int64]string{}
	for _, a := range assets {
		if a != nil && a.IP != "" {
			assetIP[a.ID] = a.IP
		}
	}
	sessionHost := map[int64]string{}
	for _, rec := range recs {
		host := ""
		if u, err := url.Parse(rec.URL); err == nil {
			host = u.Hostname()
		}
		ip := assetIP[rec.HostAssetID]
		if ip == "" {
			ip = host
		}
		if ip == "" {
			continue
		}
		sessionHost[rec.ID] = ip
		n := nodes[ip]
		if n == nil {
			n = &topoNode{ID: fmt.Sprintf("sess-%d", rec.ID), IP: ip, Services: []map[string]any{}}
			nodes[ip] = n
		}
		n.HasSession = true
		if rec.Status == db.SessionAlive {
			n.AliveSessions++
		}
	}
	nodeIDByIP := map[string]string{}
	for ip, n := range nodes {
		nodeIDByIP[ip] = n.ID
	}
	edges := []topoEdge{}
	for _, t := range tunnels {
		to := ""
		if t.Kind == "portfwd" && t.TargetHost != "" {
			if id, ok := nodeIDByIP[t.TargetHost]; ok {
				to = id
			} else {
				addr := net.JoinHostPort(t.TargetHost, strconv.Itoa(t.TargetPort))
				n := nodes[addr]
				if n == nil {
					n = &topoNode{ID: fmt.Sprintf("pf-%d", t.ID), IP: addr, Services: []map[string]any{}}
					nodes[addr] = n
					nodeIDByIP[addr] = n.ID
				}
				to = n.ID
			}
		} else if h := sessionHost[t.ViaSessionID]; h != "" {
			to = nodeIDByIP[h]
		}
		if to == "" {
			continue
		}
		edges = append(edges, topoEdge{ID: t.ID, Kind: t.Kind, From: "platform", To: to, State: t.State})
	}
	nodeList := make([]*topoNode, 0, len(nodes))
	segSet := map[string]bool{}
	for _, n := range nodes {
		n.Segment = segmentOf(n.IP, assetCSegment(assets, n.IP))
		if callbackHost != "" && n.IP == callbackHost {
			n.IsCallback = true
		}
		if n.Segment != "" {
			segSet[n.Segment] = true
		}
		nodeList = append(nodeList, n)
	}
	sort.Slice(nodeList, func(i, j int) bool { return nodeList[i].IP < nodeList[j].IP })
	if len(edges) > 0 {
		ip := callbackHost
		if ip == "" {
			ip = "平台自身"
		}
		nodeList = append(nodeList, &topoNode{ID: "platform", IP: ip, IsCallback: true, Services: []map[string]any{}})
	}
	segs := make([]string, 0, len(segSet))
	for s := range segSet {
		segs = append(segs, s)
	}
	sort.Strings(segs)
	segList := make([]topoSegment, 0, len(segs))
	for i, name := range segs {
		segList = append(segList, topoSegment{Name: name, ColorKey: fmt.Sprintf("seg-%d", i)})
	}
	return map[string]any{"nodes": nodeList, "edges": edges, "segments": segList}
}

func assetCSegment(assets []*db.Asset, ip string) string {
	for _, a := range assets {
		if a != nil && a.IP == ip {
			return a.CSegment
		}
	}
	return ""
}

func parseTaskIDQuery(w http.ResponseWriter, r *http.Request) (int64, bool) {
	v := strings.TrimSpace(r.URL.Query().Get("task_id"))
	if v == "" {
		return 0, true
	}
	id, err := strconv.ParseInt(v, 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "非法 task_id: "+v)
		return 0, false
	}
	return id, true
}

func filterSessionsByTask(recs []*db.SessionRecord, taskID int64) []*db.SessionRecord {
	if taskID <= 0 {
		return recs
	}
	filtered := recs[:0]
	for _, rec := range recs {
		if rec.CreatedByTask == taskID {
			filtered = append(filtered, rec)
		}
	}
	return filtered
}

// GET /api/intranet/topology?task_id= — 纯组装,只读。先画资产 + 会话。
func (s *Server) intranetTopology(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.pg == nil || s.sessStore == nil {
		writeErr(w, 503, "拓扑数据未就绪(DB 未连接)")
		return
	}
	taskID, ok := parseTaskIDQuery(w, r)
	if !ok {
		return
	}
	var assets []*db.Asset
	var err error
	if taskID > 0 {
		assets, err = s.m.pg.Assets().QueryByTask(taskID, "ip", 5000, 0)
	} else {
		assets, err = s.m.pg.Assets().QueryByType("ip", 5000, 0)
	}
	if err != nil {
		writeErr(w, 500, "资产读取失败: "+err.Error())
		return
	}
	recs, err := s.sessStore.List(r.Context(), "")
	if err != nil {
		writeErr(w, 500, "会话台账读取失败: "+err.Error())
		return
	}
	recs = filterSessionsByTask(recs, taskID)
	tuns := collectTopoTunnels(r.Context(), s.tunnelLive, taskID)
	writeJSON(w, 200, buildTopology(assets, recs, tuns, callbackHostForTopo()))
}

// taskIntranet 判定任务是否处于内网期(worker.intranet 短纪律变体的开关):
// 存在该任务创建的存活立足点会话。worker 每次 run 现查,会话状态变化即时生效;
// 读取失败按外网处理(不误切变体)。隧道台账本刀不移植:若后续接入,必须对
// nil 存储与读取失败保持安全,不得为了做这个检查而搬隧道台账。
func (s *Server) taskIntranet(taskID int64) bool {
	if taskID <= 0 {
		return false
	}
	ctx := context.Background()
	if s != nil && s.ctx != nil {
		ctx = s.ctx
	}
	if s != nil && s.sessStore != nil {
		recs, err := s.sessStore.List(ctx, db.SessionAlive)
		if hasLiveTaskSession(recs, err, taskID) {
			return true
		}
	}
	// 隧道台账未接线或查找失败：保持外网变体（nil-safe）。
	if s != nil && s.tunnelLive != nil {
		recs, err := s.tunnelLive.ListByTask(ctx, taskID)
		if hasLiveTaskTunnel(recs, err) {
			return true
		}
	}
	return false
}

// tunnelLiveLister 是内网变体/拓扑用的最小台账读口（*tunnelRuntime / *db.TunnelStore 满足）。
type tunnelLiveLister interface {
	ListByTask(ctx context.Context, taskID int64) ([]*db.TunnelRecord, error)
}

// hasLiveTaskTunnel 查找失败或无存活隧道一律视为外网。
func hasLiveTaskTunnel(recs []*db.TunnelRecord, err error) bool {
	if err != nil {
		return false
	}
	for _, r := range recs {
		if r != nil && r.State == db.TunnelAlive {
			return true
		}
	}
	return false
}

// hasLiveTaskSession 把「查找失败 / 非法 task / 无存活会话」一律视为外网。
func hasLiveTaskSession(recs []*db.SessionRecord, err error, taskID int64) bool {
	if err != nil || taskID <= 0 {
		return false
	}
	for _, r := range recs {
		if r != nil && r.CreatedByTask == taskID {
			return true
		}
	}
	return false
}
