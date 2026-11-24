package guard

// 批 5 B3(设计文档 HONEYPOT-DETECTION-DESIGN.md 二-B「自身防护」第 5 条):tarpit 熔断。
// Nepenthes / Cloudflare AI Labyrinth 类反爬虫迷宫用无限假页面困死抓取方、烧光
// 任务预算。本文件按「每任务每 host」计数 WebFetch 以及 Bash 里 curl/ffuf/katana/httpx
// 一类抓取调用,超过预算触发一次
// 熔断:经 Hint 回调写 hint 节点进探索图(planner 每轮 graph overview 必读 hints,
// 参照停滞检测 hint 的既有通道),提示停派该方向;之后对该 host 的抓取仍 warn
// 放行——不硬 block,防误杀真实大站。
//
// 计数器在内存里(每任务一个 Guard,见 server taskFromPG),任务重启清零:重启后
// 重新爬一遍才会再触发,代价可接受,不落库。

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/Autumn-27/norma/hook"
)

// defaultTarpitFetchBudget 是每 host 抓取调用的默认预算(settings 键
// tarpit_fetch_budget 可配,<=0 或非法值回落到它)。
const defaultTarpitFetchBudget = 40

// maxIdenticalURLTarpitHits caps how many times identical static-URL polling
// (e.g. GET /openapi/v1/challenges) contributes to a host's tarpit budget so
// control-plane status checks do not trip tarpit detection.
const maxIdenticalURLTarpitHits = 3

// TarpitConfig 是 tarpit 熔断的装配:两个回调都由 server 注入(guard 不反向
// 依赖 db/server)。
type TarpitConfig struct {
	// Budget 返回当前预算(settings tarpit_fetch_budget)。nil 或返回 <=0 → 默认 40。
	Budget func() int
	// Hint 是熔断触发(每 host 只一次)时的回调,server 装配为写探索图 hint 节点。
	// nil = 只记 guard 审计/日志。
	Hint func(host string, count int)
}

// tarpitState 是每 Guard(=每任务)的 tarpit 计数状态;经 Guard.mu 串行化。
type tarpitState struct {
	cfg     TarpitConfig
	counts  map[string]int
	urlHits map[string]int
	fired   map[string]bool // 每 host 只熔断一次
}

type tarpitTarget struct {
	host      string
	staticURL string
}

// SetTarpit 装配 tarpit 熔断。零值/再传 nil 回调只是降级(不写 hint),不报错。
func (g *Guard) SetTarpit(cfg TarpitConfig) {
	g.mu.Lock()
	g.tarpit = &tarpitState{
		cfg:     cfg,
		counts:  map[string]int{},
		urlHits: map[string]int{},
		fired:   map[string]bool{},
	}
	g.mu.Unlock()
}

func (c TarpitConfig) budget() int {
	if c.Budget == nil {
		return defaultTarpitFetchBudget
	}
	if b := c.Budget(); b > 0 {
		return b
	}
	return defaultTarpitFetchBudget
}

type tarpitScopeKey struct{}

// WithScopeKey attaches an optional isolation scope (e.g. "intent:123") to ctx
// so dynamic benchmark containers recycled across intents on default :80 do not
// accumulate cross-intent tarpit counts on the same IP.
func WithScopeKey(ctx context.Context, key string) context.Context {
	if ctx == nil || strings.TrimSpace(key) == "" {
		return ctx
	}
	return context.WithValue(ctx, tarpitScopeKey{}, strings.TrimSpace(key))
}

// ScopeKeyFrom returns the tarpit isolation scope carried on ctx, if any.
func ScopeKeyFrom(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(tarpitScopeKey{}).(string)
	return v
}

// checkTarpit 统计 WebFetch 与 Bash 抓取类命令对同一 host 的调用;超预算时熔断
// 一次(写 hint),之后对该 host 一律 warn 放行(只记审计,不 block)。非抓取 /
// 无法解析 host 的调用直接放行,不改完成语义。
func (g *Guard) checkTarpit(ctx context.Context, ev hook.Event) {
	g.mu.Lock()
	st := g.tarpit
	g.mu.Unlock()
	if st == nil {
		return
	}
	for _, target := range tarpitTargets(ev) {
		g.countTarpitTarget(ctx, ev, st, target)
	}
}

func (g *Guard) countTarpitTarget(ctx context.Context, ev hook.Event, st *tarpitState, target tarpitTarget) {
	host := target.host
	if host == "" {
		return
	}
	scope := ScopeKeyFrom(ctx)
	countKey := host
	urlKey := target.staticURL
	if scope != "" {
		countKey = scope + "|" + host
		if urlKey != "" {
			urlKey = scope + "|" + urlKey
		}
	}
	g.mu.Lock()
	if urlKey != "" {
		st.urlHits[urlKey]++
		if st.urlHits[urlKey] > maxIdenticalURLTarpitHits {
			g.mu.Unlock()
			return
		}
	}
	st.counts[countKey]++
	count := st.counts[countKey]
	budget := st.cfg.budget()
	over := count > budget
	first := over && !st.fired[countKey]
	if first {
		st.fired[countKey] = true
	}
	g.mu.Unlock()

	if !over {
		return
	}
	if first {
		// 熔断:记审计 + 回调写 hint(host/次数),提示 planner 停派该方向。
		g.record(ev.ToolName, "allow", tarpitMessage(host, count, budget), "")
		log.Printf("[guard][tarpit] host %s 抓取调用 %d 次超过预算 %d,已熔断告警(warn 放行)", host, count, budget)
		if st.cfg.Hint != nil {
			st.cfg.Hint(host, count)
		}
		return
	}
	// 已熔断过的 host:warn 放行——不硬 block(防误杀真实大站),但每次留一条
	// 轻量审计,事后能还原「熔断后仍在抓」的行为。
	g.record(ev.ToolName, "allow", "tarpit 熔断后仍抓取 "+host, "")
}

// tarpitTargets 抽出本次抓取要计数的目标。WebFetch 看 url;Bash 仅当命令位
// 是 curl/ffuf/katana/httpx 一类且非状态变更 curl 时才提取。
func tarpitTargets(ev hook.Event) []tarpitTarget {
	switch ev.ToolName {
	case "WebFetch":
		var in struct {
			URL string `json:"url"`
		}
		if json.Unmarshal(ev.Input, &in) != nil || in.URL == "" {
			return nil
		}
		u, err := url.Parse(in.URL)
		if err != nil {
			return nil
		}
		host := tarpitHostKey(u)
		if host == "" {
			return nil
		}
		return []tarpitTarget{{host: host, staticURL: canonicalStaticTarpitURL(u, in.URL)}}
	case "Bash":
		var in struct {
			Command string `json:"command"`
		}
		if json.Unmarshal(ev.Input, &in) != nil {
			return nil
		}
		return bashFetchTargets(in.Command)
	default:
		return nil
	}
}

func tarpitHostKey(u *url.URL) string {
	if u == nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ""
	}
	port := u.Port()
	if port == "" || (strings.EqualFold(u.Scheme, "http") && port == "80") || (strings.EqualFold(u.Scheme, "https") && port == "443") {
		return host
	}
	return net.JoinHostPort(host, port)
}

func canonicalStaticTarpitURL(u *url.URL, raw string) string {
	if u == nil || strings.Contains(raw, "FUZZ") {
		return ""
	}
	host := tarpitHostKey(u)
	if host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	s := scheme + "://" + host + u.EscapedPath()
	if u.RawQuery != "" {
		s += "?" + u.RawQuery
	}
	return s
}

// tarpitMessage 是熔断审计/hint 共用的文案:疑似 tarpit 迷宫(host,次数)。
func tarpitMessage(host string, count, budget int) string {
	return "疑似 tarpit 迷宫(" + host + ",抓取 " + strconv.Itoa(count) + " 次,预算 " + strconv.Itoa(budget) + ")"
}

var bashFetchTools = map[string]bool{
	"curl": true, "ffuf": true, "katana": true, "httpx": true,
}

var bashFetchPrefixes = map[string]bool{
	"sudo": true, "doas": true, "command": true, "time": true,
	"env": true, "nice": true, "nohup": true, "stdbuf": true, "timeout": true,
}

var bashFetchURLFlags = map[string]bool{
	"-u": true, "--url": true, "--host": true, "-host": true,
}

// bashFetchHosts 从 Bash 命令里抽出抓取目标 host。非抓取类(echo/nmap 等)
// 不计;命令位没有 curl/ffuf/katana/httpx 则返回空。
func bashFetchHosts(command string) []string {
	targets := bashFetchTargets(command)
	if len(targets) == 0 {
		return nil
	}
	out := make([]string, 0, len(targets))
	seen := map[string]bool{}
	for _, t := range targets {
		if t.host == "" || seen[t.host] {
			continue
		}
		seen[t.host] = true
		out = append(out, t.host)
	}
	return out
}

func bashFetchTargets(command string) []tarpitTarget {
	var out []tarpitTarget
	seen := map[string]bool{}
	for _, seg := range splitBashSegments(command) {
		tool := fetchToolInCommandPosition(seg)
		if tool == "" {
			continue
		}
		if tool == "curl" && curlSegmentIsMutation(seg) {
			continue
		}
		for _, target := range extractSegmentFetchTargets(tool, seg) {
			key := target.host + "\x00" + target.staticURL
			if target.host == "" || seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, target)
		}
	}
	return out
}

func splitBashSegments(command string) []string {
	var segs []string
	var cur strings.Builder
	var quote byte
	flush := func() {
		if s := strings.TrimSpace(cur.String()); s != "" {
			segs = append(segs, s)
		}
		cur.Reset()
	}
	for i := 0; i < len(command); i++ {
		c := command[i]
		if quote == '\'' {
			cur.WriteByte(c)
			if c == '\'' {
				quote = 0
			}
			continue
		}
		if c == '\\' && i+1 < len(command) {
			cur.WriteByte(c)
			i++
			cur.WriteByte(command[i])
			continue
		}
		if quote == '"' {
			cur.WriteByte(c)
			if c == '"' {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			cur.WriteByte(c)
		case '|', ';', '&', '\n', '\r':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return segs
}

func fetchToolInCommandPosition(seg string) string {
	for _, tok := range splitShellTokens(seg) {
		tok = strings.Trim(tok, `"'`)
		if tok == "" {
			continue
		}
		if strings.Contains(tok, "=") && !strings.HasPrefix(tok, "-") {
			continue // ENV=val 前缀
		}
		base := bashTokBase(tok)
		if bashFetchPrefixes[base] {
			continue
		}
		if bashFetchTools[base] {
			return base
		}
		return ""
	}
	return ""
}

func curlSegmentIsMutation(seg string) bool {
	toks := splitShellTokens(seg)
	expectMethod := false
	for _, tok := range toks {
		tok = strings.Trim(tok, `"'`)
		if tok == "" {
			continue
		}
		if expectMethod {
			expectMethod = false
			switch strings.ToUpper(tok) {
			case "POST", "PUT", "DELETE", "PATCH":
				return true
			}
			continue
		}
		switch {
		case tok == "-X" || tok == "--request":
			expectMethod = true
		case strings.HasPrefix(tok, "-X") && len(tok) > 2:
			switch strings.ToUpper(tok[2:]) {
			case "POST", "PUT", "DELETE", "PATCH":
				return true
			}
		case strings.HasPrefix(tok, "--request="):
			switch strings.ToUpper(strings.TrimPrefix(tok, "--request=")) {
			case "POST", "PUT", "DELETE", "PATCH":
				return true
			}
		case tok == "-d" || tok == "--data" || tok == "--data-raw" ||
			tok == "--data-binary" || tok == "--data-urlencode" ||
			tok == "--json" || tok == "-F" || tok == "--form":
			return true
		case strings.HasPrefix(tok, "--data=") || strings.HasPrefix(tok, "--data-raw=") ||
			strings.HasPrefix(tok, "--data-binary=") || strings.HasPrefix(tok, "--data-urlencode=") ||
			strings.HasPrefix(tok, "--json=") || strings.HasPrefix(tok, "--form="):
			return true
		}
	}
	return false
}

func bashTokBase(tok string) string {
	base := strings.ToLower(path.Base(tok))
	return strings.TrimSuffix(base, ".exe")
}

func splitShellTokens(seg string) []string {
	var toks []string
	var cur strings.Builder
	var quote byte
	active := false
	flush := func() {
		if active {
			toks = append(toks, cur.String())
			cur.Reset()
			active = false
		}
	}
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		if quote == '\'' {
			if c == '\'' {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
			continue
		}
		if c == '\\' && i+1 < len(seg) {
			i++
			cur.WriteByte(seg[i])
			active = true
			continue
		}
		if quote == '"' {
			if c == '"' {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			active = true
		case ' ', '\t':
			flush()
		default:
			cur.WriteByte(c)
			active = true
		}
	}
	flush()
	return toks
}

func extractSegmentFetchTargets(tool, seg string) []tarpitTarget {
	var out []tarpitTarget
	isCrawler := tool == "ffuf" || tool == "katana"
	addURL := func(raw string) {
		raw = strings.Trim(raw, `"'`)
		if raw == "" {
			return
		}
		var u *url.URL
		var err error
		if strings.Contains(raw, "://") {
			u, err = url.Parse(raw)
		} else {
			// -u example.com 这类无 scheme 的值,补一个 http:// 再解析;解不到就跳过。
			u, err = url.Parse("http://" + raw)
			if err == nil && !strings.Contains(u.Hostname(), ".") && net.ParseIP(u.Hostname()) == nil {
				return
			}
		}
		if err != nil {
			return
		}
		host := tarpitHostKey(u)
		if host == "" {
			return
		}
		staticURL := ""
		if !isCrawler {
			staticURL = canonicalStaticTarpitURL(u, raw)
		}
		out = append(out, tarpitTarget{host: host, staticURL: staticURL})
	}

	for _, raw := range reScheme.FindAllString(seg, -1) {
		addURL(raw)
	}

	// 抓取工具的 -u/--url 值(可能没有 scheme)。
	toks := splitShellTokens(seg)
	takeNext := false
	for _, tok := range toks {
		tok = strings.Trim(tok, `"'`)
		if tok == "" {
			continue
		}
		if takeNext {
			addURL(tok)
			takeNext = false
			continue
		}
		if i := strings.IndexByte(tok, '='); i > 0 {
			name, val := tok[:i], tok[i+1:]
			if bashFetchURLFlags[name] {
				addURL(val)
			}
			continue
		}
		if bashFetchURLFlags[tok] {
			takeNext = true
		}
	}
	return out
}
