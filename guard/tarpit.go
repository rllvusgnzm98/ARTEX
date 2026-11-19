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
	cfg    TarpitConfig
	counts map[string]int
	fired  map[string]bool // 每 host 只熔断一次
}

// SetTarpit 装配 tarpit 熔断。零值/再传 nil 回调只是降级(不写 hint),不报错。
func (g *Guard) SetTarpit(cfg TarpitConfig) {
	g.mu.Lock()
	g.tarpit = &tarpitState{cfg: cfg, counts: map[string]int{}, fired: map[string]bool{}}
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

// checkTarpit 统计 WebFetch 与 Bash 抓取类命令对同一 host 的调用;超预算时熔断
// 一次(写 hint),之后对该 host 一律 warn 放行(只记审计,不 block)。非抓取 /
// 无法解析 host 的调用直接放行,不改完成语义。
func (g *Guard) checkTarpit(ev hook.Event) {
	g.mu.Lock()
	st := g.tarpit
	g.mu.Unlock()
	if st == nil {
		return
	}
	for _, host := range tarpitHosts(ev) {
		g.countTarpitHost(ev, st, host)
	}
}

func (g *Guard) countTarpitHost(ev hook.Event, st *tarpitState, host string) {
	if host == "" {
		return
	}
	g.mu.Lock()
	st.counts[host]++
	count := st.counts[host]
	budget := st.cfg.budget()
	over := count > budget
	first := over && !st.fired[host]
	if first {
		st.fired[host] = true
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

// tarpitHosts 抽出本次抓取要计数的 host。WebFetch 看 url;Bash 仅当命令位
// 是 curl/ffuf/katana/httpx 一类时才提取。解析不到则返回空(跳过计数)。
func tarpitHosts(ev hook.Event) []string {
	switch ev.ToolName {
	case "WebFetch":
		var in struct {
			URL string `json:"url"`
		}
		if json.Unmarshal(ev.Input, &in) != nil || in.URL == "" {
			return nil
		}
		u, err := url.Parse(in.URL)
		if err != nil || u.Hostname() == "" {
			return nil
		}
		return []string{u.Hostname()}
	case "Bash":
		var in struct {
			Command string `json:"command"`
		}
		if json.Unmarshal(ev.Input, &in) != nil {
			return nil
		}
		return bashFetchHosts(in.Command)
	default:
		return nil
	}
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
	if !bashInvokesFetch(command) {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, host := range extractBashFetchHosts(command) {
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		out = append(out, host)
	}
	return out
}

func bashInvokesFetch(command string) bool {
	for _, seg := range splitBashSegments(command) {
		if fetchToolInCommandPosition(seg) {
			return true
		}
	}
	return false
}

func splitBashSegments(command string) []string {
	return strings.FieldsFunc(command, func(r rune) bool {
		return r == '|' || r == ';' || r == '&' || r == '\n'
	})
}

func fetchToolInCommandPosition(seg string) bool {
	for _, tok := range strings.Fields(seg) {
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
		return bashFetchTools[base]
	}
	return false
}

func bashTokBase(tok string) string {
	base := strings.ToLower(path.Base(tok))
	return strings.TrimSuffix(base, ".exe")
}

func extractBashFetchHosts(command string) []string {
	var out []string
	addURL := func(raw string) {
		raw = strings.Trim(raw, `"'`)
		if raw == "" {
			return
		}
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			out = append(out, u.Hostname())
			return
		}
		// -u example.com 这类无 scheme 的值,补一个 http:// 再解析;解不到就跳过。
		if u, err := url.Parse("http://" + raw); err == nil && u.Hostname() != "" && !strings.Contains(raw, "://") {
			if strings.Contains(u.Hostname(), ".") || net.ParseIP(u.Hostname()) != nil {
				out = append(out, u.Hostname())
			}
		}
	}

	for _, raw := range reScheme.FindAllString(command, -1) {
		addURL(raw)
	}

	// 抓取工具的 -u/--url 值(可能没有 scheme)。
	toks := reShellSplit.Split(command, -1)
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
