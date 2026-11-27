package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/notify"
)

// 资产同步（Shodan 数据源）。
//
// Shodan 通过 REST API（https://api.shodan.io）提供主机端口、域名/子域、HTTP 标题、
// 组件指纹、SSL 证书与组织信息。支持：
//   - 标准 Shodan 检索语法（GET /shodan/host/search），如 hostname:example.com、
//     org:"Acme"、ssl:"example.com"、net:1.2.3.0/24；
//   - 单 IP 直查（输入纯 IPv4/IPv6 时走 GET /shodan/host/{ip}，不消耗 query credits）。
//
// 凭据存 settings 表（shodan.key），沿用 notify.IsMasked 掩码约定；出网走全局代理
// （GlobalProxy），不经 MITM 录制代理。同步结果归入资产图并写入命名资产合集
// （source='shodan'），便于了解同公司/同域名业务面与辅助口令字典生成。
var (
	shodanAPIBase   = "https://api.shodan.io"
	shodanPageDelay = 1100 * time.Millisecond // Shodan API 限速 1 req/s，翻页间隔防 429
)

const (
	shodanMaxResults    = 5000
	shodanPreviewMax    = 100
	shodanPageSize      = 100 // Shodan /shodan/host/search 固定每页 100 条
	settingShodanKey    = "shodan.key"
	shodanClientTimeout = 25 * time.Second
)

// shodanRow 是预览返回给前端的一行。
type shodanRow struct {
	IP        string `json:"ip"`
	Port      string `json:"port"`
	Transport string `json:"transport"`
	Hostnames string `json:"hostnames"`
	Domains   string `json:"domains"`
	Product   string `json:"product"`
	Org       string `json:"org"`
	Title     string `json:"title"`
	Module    string `json:"module"`
}

type shodanAPIInfo struct {
	Plan         string `json:"plan"`
	QueryCredits int    `json:"query_credits"`
	ScanCredits  int    `json:"scan_credits"`
	Error        string `json:"error"`
}

type shodanFavicon struct {
	Hash json.RawMessage `json:"hash"`
}

type shodanHTTP struct {
	Host       string                 `json:"host"`
	Title      string                 `json:"title"`
	Server     string                 `json:"server"`
	Status     int                    `json:"status"`
	Favicon    *shodanFavicon         `json:"favicon"`
	Components map[string]interface{} `json:"components"`
}

type shodanMeta struct {
	Module string `json:"module"`
}

type shodanMatch struct {
	IPStr     string          `json:"ip_str"`
	Port      int             `json:"port"`
	Transport string          `json:"transport"`
	Hostnames []string        `json:"hostnames"`
	Domains   []string        `json:"domains"`
	Org       string          `json:"org"`
	ISP       string          `json:"isp"`
	ASN       string          `json:"asn"`
	Product   string          `json:"product"`
	Version   string          `json:"version"`
	Title     string          `json:"title"`
	HTTP      *shodanHTTP     `json:"http"`
	SSL       json.RawMessage `json:"ssl"`
	Shodan    *shodanMeta     `json:"_shodan"`
}

type shodanSearchResp struct {
	Total   int           `json:"total"`
	Matches []shodanMatch `json:"matches"`
	Error   string        `json:"error"`
}

type shodanHostResp struct {
	IPStr     string        `json:"ip_str"`
	Org       string        `json:"org"`
	ISP       string        `json:"isp"`
	ASN       string        `json:"asn"`
	Hostnames []string      `json:"hostnames"`
	Domains   []string      `json:"domains"`
	Data      []shodanMatch `json:"data"`
	Error     string        `json:"error"`
}

func (s *Server) shodanKey() string {
	key, _, _ := s.m.pg.GetSetting(settingShodanKey)
	return strings.TrimSpace(key)
}

func (s *Server) shodanGet(ctx context.Context, key, path string, extra url.Values, out any) error {
	q := url.Values{}
	q.Set("key", key)
	for k, vs := range extra {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	u := strings.TrimRight(shodanAPIBase, "/") + path + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := s.externalSyncClient(shodanClientTimeout).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &errBody)
		detail := strings.TrimSpace(errBody.Error)
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			if detail != "" {
				return fmt.Errorf("Shodan 认证失败（HTTP 401）：%s", detail)
			}
			return fmt.Errorf("Shodan 认证失败（HTTP 401），请检查 API Key")
		case http.StatusForbidden:
			if detail != "" {
				return fmt.Errorf("Shodan 拒绝访问（HTTP 403，可能受限于账号套餐或查询积分）：%s", detail)
			}
			return fmt.Errorf("Shodan 拒绝访问（HTTP 403），当前账号套餐可能不支持该检索接口")
		case http.StatusNotFound:
			if detail != "" {
				return fmt.Errorf("Shodan 未收录目标信息（HTTP 404）：%s", detail)
			}
			return fmt.Errorf("Shodan 未收录该目标信息（HTTP 404）")
		case http.StatusTooManyRequests:
			return fmt.Errorf("Shodan 请求过于频繁（HTTP 429），请稍后重试")
		default:
			if detail != "" {
				return fmt.Errorf("Shodan 返回 HTTP %d：%s", resp.StatusCode, detail)
			}
			return fmt.Errorf("Shodan 返回 HTTP %d", resp.StatusCode)
		}
	}
	return json.Unmarshal(body, out)
}

func (s *Server) shodanProbe(ctx context.Context, key string) (shodanAPIInfo, error) {
	var info shodanAPIInfo
	if err := s.shodanGet(ctx, key, "/api-info", url.Values{}, &info); err != nil {
		return info, err
	}
	if info.Error != "" {
		return info, fmt.Errorf("%s", info.Error)
	}
	return info, nil
}

func (s *Server) shodanHostLookup(ctx context.Context, key, ip string) (shodanSearchResp, error) {
	var hr shodanHostResp
	if err := s.shodanGet(ctx, key, "/shodan/host/"+url.PathEscape(ip), url.Values{}, &hr); err != nil {
		return shodanSearchResp{}, err
	}
	if hr.Error != "" {
		return shodanSearchResp{}, fmt.Errorf("%s", hr.Error)
	}
	matches := make([]shodanMatch, 0, len(hr.Data))
	for _, m := range hr.Data {
		if m.IPStr == "" {
			m.IPStr = hr.IPStr
		}
		if m.IPStr == "" {
			m.IPStr = ip
		}
		if m.Org == "" {
			m.Org = hr.Org
		}
		if len(m.Hostnames) == 0 {
			m.Hostnames = hr.Hostnames
		}
		if len(m.Domains) == 0 {
			m.Domains = hr.Domains
		}
		matches = append(matches, m)
	}
	return shodanSearchResp{Total: len(matches), Matches: matches}, nil
}

func (s *Server) shodanSearchPage(ctx context.Context, key, query string, page int) (shodanSearchResp, error) {
	var out shodanSearchResp
	extra := url.Values{}
	extra.Set("query", query)
	if page > 1 {
		extra.Set("page", strconv.Itoa(page))
	}
	if err := s.shodanGet(ctx, key, "/shodan/host/search", extra, &out); err != nil {
		return out, err
	}
	if out.Error != "" {
		return out, fmt.Errorf("%s", out.Error)
	}
	return out, nil
}

func shodanMatchTitle(m shodanMatch) string {
	if m.HTTP != nil && strings.TrimSpace(m.HTTP.Title) != "" {
		return strings.TrimSpace(m.HTTP.Title)
	}
	return strings.TrimSpace(m.Title)
}

func shodanMatchModule(m shodanMatch) string {
	if m.Shodan != nil {
		return strings.ToLower(strings.TrimSpace(m.Shodan.Module))
	}
	return ""
}

func shodanMatchProduct(m shodanMatch) string {
	p := strings.TrimSpace(m.Product)
	v := strings.TrimSpace(m.Version)
	if p != "" && v != "" {
		return p + " " + v
	}
	if p != "" {
		return p
	}
	if m.HTTP != nil && strings.TrimSpace(m.HTTP.Server) != "" {
		return strings.TrimSpace(m.HTTP.Server)
	}
	return shodanMatchModule(m)
}

func matchToShodanRow(m shodanMatch) shodanRow {
	port := ""
	if m.Port > 0 {
		port = strconv.Itoa(m.Port)
	}
	return shodanRow{
		IP:        strings.TrimSpace(m.IPStr),
		Port:      port,
		Transport: strings.ToLower(strings.TrimSpace(m.Transport)),
		Hostnames: strings.Join(dedupCleanStrings(m.Hostnames), ", "),
		Domains:   strings.Join(dedupCleanStrings(m.Domains), ", "),
		Product:   shodanMatchProduct(m),
		Org:       strings.TrimSpace(m.Org),
		Title:     shodanMatchTitle(m),
		Module:    shodanMatchModule(m),
	}
}

// ---------- GET /api/sync/shodan/status ----------
func (s *Server) syncShodanStatus(w http.ResponseWriter, r *http.Request) {
	if s.pg(w) == nil {
		return
	}
	key := s.shodanKey()
	configured := key != ""
	reachable := false
	plan := ""
	queryCredits := 0
	scanCredits := 0
	errMsg := ""
	if configured {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		info, err := s.shodanProbe(ctx, key)
		if err == nil {
			reachable = true
			plan = info.Plan
			queryCredits = info.QueryCredits
			scanCredits = info.ScanCredits
		} else {
			errMsg = err.Error()
		}
	}
	writeJSON(w, 200, map[string]any{
		"configured":    configured,
		"reachable":     reachable,
		"plan":          plan,
		"query_credits": queryCredits,
		"scan_credits":  scanCredits,
		"error":         errMsg,
	})
}

// ---------- POST /api/sync/shodan/datasource ----------
func (s *Server) syncShodanDatasource(w http.ResponseWriter, r *http.Request) {
	if s.pg(w) == nil {
		return
	}
	var body struct {
		Key string `json:"key"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "invalid JSON: "+err.Error())
		return
	}
	curKey := s.shodanKey()
	newKey := curKey
	if k := strings.TrimSpace(body.Key); k != "" && !notify.IsMasked(k) {
		newKey = k
	}
	if newKey != curKey {
		if err := s.m.pg.SetSetting(settingShodanKey, newKey); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	writeJSON(w, 200, map[string]any{
		"configured": newKey != "",
	})
}

// ---------- POST /api/sync/shodan/query ---------- (预览，不写库)
func (s *Server) syncShodanQuery(w http.ResponseWriter, r *http.Request) {
	if s.pg(w) == nil {
		return
	}
	var body struct {
		Query string `json:"query"`
		Size  int    `json:"size"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "invalid JSON: "+err.Error())
		return
	}
	query := strings.TrimSpace(body.Query)
	if query == "" {
		writeErr(w, 400, "query 不能为空")
		return
	}
	key := s.shodanKey()
	if key == "" {
		writeErr(w, 400, "未配置 Shodan API Key，请先在上方保存")
		return
	}
	size := body.Size
	if size <= 0 || size > shodanPreviewMax {
		size = shodanPreviewMax
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	var (
		resp shodanSearchResp
		err  error
		mode = "search"
	)
	if ip := net.ParseIP(query); ip != nil {
		mode = "host"
		resp, err = s.shodanHostLookup(ctx, key, ip.String())
	} else {
		resp, err = s.shodanSearchPage(ctx, key, query, 1)
	}
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	limit := min(size, len(resp.Matches))
	rows := make([]shodanRow, 0, limit)
	for i := 0; i < limit; i++ {
		rows = append(rows, matchToShodanRow(resp.Matches[i]))
	}
	writeJSON(w, 200, map[string]any{
		"total": resp.Total,
		"mode":  mode,
		"rows":  rows,
	})
}

// ---------- POST /api/sync/shodan/sync ---------- (检索 + 导入资产 + 归入合集)
func (s *Server) syncShodanRun(w http.ResponseWriter, r *http.Request) {
	if s.pg(w) == nil {
		return
	}
	as := s.assetStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	var req struct {
		Query          string `json:"query"`
		Size           int    `json:"size"`
		CollectionName string `json:"collection_name"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "invalid JSON: "+err.Error())
		return
	}
	query := strings.TrimSpace(req.Query)
	if query == "" {
		writeErr(w, 400, "query 不能为空")
		return
	}
	key := s.shodanKey()
	if key == "" {
		writeErr(w, 400, "未配置 Shodan API Key，请先在上方保存")
		return
	}
	name := strings.TrimSpace(req.CollectionName)
	if name == "" {
		name = query
	}
	target := req.Size
	if target <= 0 || target > shodanMaxResults {
		target = shodanMaxResults
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	synced := map[string]int{"service": 0, "ip": 0, "subdomain": 0, "domain": 0}
	var warnings, errs []string
	memberSet := map[int64]struct{}{}
	imported := 0
	shodanTotal := 0
	truncated := false

	ingestBatch := func(matches []shodanMatch) {
		for _, m := range matches {
			if imported >= target {
				truncated = true
				break
			}
			ids, e := shodanIngest(as, m, synced)
			if e != "" {
				errs = append(errs, e)
			}
			for _, id := range ids {
				memberSet[id] = struct{}{}
			}
			imported++
		}
	}

	if ip := net.ParseIP(query); ip != nil {
		resp, err := s.shodanHostLookup(ctx, key, ip.String())
		if err != nil {
			errs = append(errs, "IP 主机查询失败: "+err.Error())
		} else {
			shodanTotal = resp.Total
			ingestBatch(resp.Matches)
			if shodanTotal > imported {
				truncated = true
			}
		}
	} else {
		for page := 1; imported < target; page++ {
			if page > 1 && shodanPageDelay > 0 {
				select {
				case <-ctx.Done():
					errs = append(errs, "同步已取消或超时")
					goto finalize
				case <-time.After(shodanPageDelay):
				}
			}
			resp, err := s.shodanSearchPage(ctx, key, query, page)
			if err != nil {
				errs = append(errs, fmt.Sprintf("第 %d 页拉取失败: %v", page, err))
				break
			}
			if page == 1 {
				shodanTotal = resp.Total
			}
			if len(resp.Matches) == 0 {
				break
			}
			ingestBatch(resp.Matches)
			if len(resp.Matches) < shodanPageSize || imported >= shodanTotal {
				break
			}
			if imported >= target {
				truncated = shodanTotal > imported
				break
			}
		}
	}

finalize:
	memberIDs := make([]int64, 0, len(memberSet))
	for id := range memberSet {
		memberIDs = append(memberIDs, id)
	}
	var collection map[string]any
	if cid, err := s.m.pg.UpsertCollection(name, query, "shodan"); err != nil {
		errs = append(errs, "创建合集失败: "+err.Error())
	} else {
		if err := s.m.pg.AddCollectionMembers(cid, memberIDs); err != nil {
			errs = append(errs, "合集写入成员失败: "+err.Error())
		}
		collection = map[string]any{"id": cid, "name": name, "members": len(memberIDs)}
	}

	writeJSON(w, 200, map[string]any{
		"synced":     synced,
		"total":      shodanTotal,
		"imported":   imported,
		"truncated":  truncated,
		"collection": collection,
		"warnings":   warnings,
		"errors":     errs,
	})
}

// shodanIngest maps one Shodan service match into asset-graph upserts.
func shodanIngest(as *db.AssetStore, m shodanMatch, synced map[string]int) (assetIDs []int64, errStr string) {
	ip := strings.TrimSpace(m.IPStr)
	module := shodanMatchModule(m)
	add := func(id int64) {
		if id > 0 {
			assetIDs = append(assetIDs, id)
		}
	}

	// 收集干净的域名与主机名（过滤通配符与 IP 字面量）。
	rootSet := map[string]struct{}{}
	hostSet := map[string]struct{}{}
	addDomain := func(d string) {
		d = cleanShodanHostname(d)
		if d != "" && net.ParseIP(d) == nil {
			rootSet[d] = struct{}{}
		}
	}
	addHost := func(h string) {
		h = cleanShodanHostname(h)
		if h != "" && net.ParseIP(h) == nil {
			hostSet[h] = struct{}{}
		}
	}
	for _, d := range m.Domains {
		addDomain(d)
	}
	for _, h := range m.Hostnames {
		addHost(h)
	}
	httpHost := ""
	if m.HTTP != nil && strings.TrimSpace(m.HTTP.Host) != "" {
		_, hh, _ := splitFofaHost(m.HTTP.Host)
		hh = cleanShodanHostname(hh)
		if hh != "" {
			httpHost = hh
			if net.ParseIP(hh) == nil {
				addHost(hh)
			}
		}
	}

	hosts := sortedShodanKeys(hostSet)
	roots := sortedShodanKeys(rootSet)

	// 1. IP 资产（含绑定域名与开放端口服务）。
	if net.ParseIP(ip) != nil {
		var openPorts []db.PortService
		if m.Port > 0 && m.Port <= 65535 {
			svc := deriveShodanServiceName(m)
			openPorts = []db.PortService{{Port: m.Port, Service: svc}}
		}
		if id, err := as.UpsertIP(db.UpsertIPReq{IP: ip, BoundDomains: hosts, OpenPorts: openPorts}); err == nil {
			synced["ip"]++
			add(id)
		} else {
			errStr = "IP " + ip + " 入库失败: " + err.Error()
		}
	}

	// 2. 根域名与子域名。
	for _, d := range roots {
		if id, err := as.UpsertRootDomain(db.UpsertRootDomainReq{Domain: d}); err == nil {
			synced["domain"]++
			add(id)
		}
	}
	for _, h := range hosts {
		if _, isRoot := rootSet[h]; isRoot {
			continue
		}
		if id, err := as.UpsertSubdomain(db.UpsertSubdomainReq{Domain: h}); err == nil {
			synced["subdomain"]++
			add(id)
		}
	}

	// 3. HTTP(S) 服务 vs 其它端口服务。
	isHTTP := m.HTTP != nil || strings.HasPrefix(module, "http")
	if isHTTP && m.Port > 0 && m.Port <= 65535 {
		hasSSL := len(m.SSL) > 0 && string(m.SSL) != "null"
		scheme := "http"
		if hasSSL || strings.HasPrefix(module, "https") || m.Port == 443 || m.Port == 8443 {
			scheme = "https"
		}
		targetHost := httpHost
		if targetHost == "" && len(hosts) > 0 {
			targetHost = hosts[0]
		}
		if targetHost == "" {
			targetHost = ip
		}
		u := buildAssetHTTPURL(scheme, scheme, targetHost, strconv.Itoa(m.Port))
		if u != "" {
			var statusPtr *int
			if m.HTTP != nil && m.HTTP.Status > 0 {
				st := m.HTTP.Status
				statusPtr = &st
			}
			fav := ""
			if m.HTTP != nil && m.HTTP.Favicon != nil && len(m.HTTP.Favicon.Hash) > 0 {
				raw := strings.Trim(strings.TrimSpace(string(m.HTTP.Favicon.Hash)), `"`)
				if raw != "" && raw != "null" {
					fav = raw
				}
			}
			if id, err := as.UpsertHTTPService(db.UpsertHTTPServiceReq{
				URL:          u,
				PageTitle:    shodanMatchTitle(m),
				StatusCode:   statusPtr,
				FaviconMMH3:  fav,
				Technologies: shodanTechnologies(m),
				IP:           ip,
			}); err == nil {
				synced["service"]++
				add(id)
			} else {
				errStr = "HTTP 服务 " + u + " 入库失败: " + err.Error()
			}
		}
	} else if m.Port > 0 && m.Port <= 65535 {
		svc := deriveShodanServiceName(m)
		d := ""
		if len(hosts) > 0 {
			d = hosts[0]
		} else if len(roots) > 0 {
			d = roots[0]
		}
		if d != "" || net.ParseIP(ip) != nil {
			if id, err := as.UpsertOtherService(db.UpsertOtherServiceReq{
				Domain:      d,
				IP:          ip,
				Port:        m.Port,
				ServiceName: svc,
			}); err == nil {
				synced["service"]++
				add(id)
			}
		}
	}

	return assetIDs, errStr
}

func cleanShodanHostname(raw string) string {
	h := strings.ToLower(strings.TrimSpace(raw))
	h = strings.TrimSuffix(h, ".")
	if h == "" || strings.ContainsAny(h, "* /\\?#@") {
		return ""
	}
	return h
}

func deriveShodanServiceName(m shodanMatch) string {
	mod := shodanMatchModule(m)
	if mod != "" {
		// Strip noisy Shodan module suffixes like "https-simple-new" → "https", "ssh-simple" → "ssh".
		if i := strings.IndexByte(mod, '-'); i > 0 {
			mod = mod[:i]
		}
		return mod
	}
	if p := strings.ToLower(strings.TrimSpace(m.Product)); p != "" {
		if fields := strings.Fields(p); len(fields) > 0 {
			return fields[0]
		}
	}
	if tr := strings.ToLower(strings.TrimSpace(m.Transport)); tr != "" {
		return tr
	}
	return "tcp"
}

func shodanTechnologies(m shodanMatch) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		k := strings.ToLower(s)
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, s)
	}
	if p := strings.TrimSpace(m.Product); p != "" {
		if v := strings.TrimSpace(m.Version); v != "" {
			add(p + " " + v)
		} else {
			add(p)
		}
	}
	if m.HTTP != nil {
		add(m.HTTP.Server)
		if len(m.HTTP.Components) > 0 {
			names := make([]string, 0, len(m.HTTP.Components))
			for k := range m.HTTP.Components {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, name := range names {
				if len(out) >= 20 {
					break
				}
				add(name)
			}
		}
	}
	return out
}

func dedupCleanStrings(xs []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, x := range xs {
		x = strings.TrimSpace(x)
		if x == "" {
			continue
		}
		k := strings.ToLower(x)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, x)
	}
	return out
}

func sortedShodanKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
