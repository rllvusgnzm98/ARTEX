package guard

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

// ExtractBriefHosts 从任务书(目标/描述文本)提取**显式指令包含的地址**:
//   - 完整 http(s) URL 的 host(URL 字面值本身就是一条访问指令,无需指令动词);
//   - 裸 IP 字面值(带可选端口、CIDR 不计),但仅当它所在的分句带有访问类
//     指令动词(访问/探测/检测/健康检查/GET/POST/curl/ping/nmap/扫描…)时才收,
//     避免把「本机地址 x.x.x.x」这类回连说明当成目标。
//
// 保守排除:
//   - example.com/example.net/example.org 与 RFC5737 示例 IP 段等占位符;
//   - 模板变量残留({{var}}、${var}):host 本身含 {} 或 $ 的一概不收;
//   - loopback / unspecified / multicast / link-local / 广播地址;
//   - 「本机/攻击机/回连/监听 x.x.x.x」上下文中的操作员侧地址。
//
// 提取语义刻意窄于 ExtractHosts:任务书登记的是授权范围,宁缺勿滥。
var (
	// 中文句读(\x{3000}-\x{303F}、全角 \x{FF00}-\x{FF65})不属于 URL,必须在
	// 字符集里排除——否则 `http://a。然后` 会把后续正文整段吞进匹配。
	reBriefURL = regexp.MustCompile(`(?i)\bhttps?://[^\s'"<>|` + "`" + `\x{3000}-\x{303F}\x{FF00}-\x{FF65}]+`)
	reBriefIP  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b`)
	// 访问类指令动词:同一分句内出现才接受裸 IP。中英文都覆盖。
	reBriefDirective = regexp.MustCompile(`(?i)(访问|探测|检测|健康|检查|预检|连通|扫描|登[录陆]|连接|必须|\bget\b|\bpost\b|\bcurl\b|\bping\b|\bnmap\b|\bscan\b|\bprobe\b|\bcheck\b|\bfetch\b)`)
	// 否定/排除语境词：分句内出现在 URL/IP 之前时视为显式禁区，严禁自动加入 seed scope。
	briefNegationKeywords = []string{
		"禁止", "严禁", "不要", "不得", "切勿", "请勿", "勿碰", "勿访", "勿扫", "排除",
		"范围外", "不测", "不碰", "跳过", "忽略", "不在授权", "非授权",
		"out of scope", "out-of-scope", "do not", "don't", "never ",
		"exclude", "excluded", "forbidden", "prohibited", "off-limits", "avoid ",
	}
	// 操作员侧/回连基础设施词：出现在 URL/IP 邻近前文窗口时跳过，不视为目标。
	briefCallbackKeywords = []string{
		"本机", "攻击机", "回连", "回调", "监听", "外带",
		"callback", "lhost", "reverse", "oob", "interactsh", "dnslog", "webhook",
	}
)

// briefPlaceholderHost 判断是否是文档/示例占位符 host。
func briefPlaceholderHost(h string) bool {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	switch h {
	case "example.com", "example.net", "example.org", "example.edu",
		"localhost", "host", "target":
		return true
	}
	for _, p := range []string{".example.com", ".example.net", ".example.org", ".example", ".localhost"} {
		if strings.HasSuffix(h, p) {
			return true
		}
	}
	if ip := net.ParseIP(h); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			// RFC5737 文档示例段:192.0.2.0/24、198.51.100.0/24、203.0.113.0/24。
			if v4[0] == 192 && v4[1] == 0 && v4[2] == 2 {
				return true
			}
			if v4[0] == 198 && v4[1] == 51 && v4[2] == 100 {
				return true
			}
			if v4[0] == 203 && v4[1] == 0 && v4[2] == 113 {
				return true
			}
		}
	}
	return false
}

// briefUsableIP 过滤不应进入任务范围的 IP:loopback/unspecified/multicast/
// link-local/广播与 0.x。RFC1918 内网地址**保留**——CTF/内网靶机正是任务目标。
func briefUsableIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil && (v4[0] == 0 || v4[0] == 255) {
		return false
	}
	return true
}

// isCallbackContext 判断分句里位于 idx 处的 URL/IP 是否落在「本机/攻击机/回连/
// 回调/监听/OOB」等说明词的邻近前文窗口内（向前 36 字节）——这类地址是操作员侧设施，不是任务目标。
func isCallbackContext(sent string, idx int) bool {
	lo := idx - 36
	if lo < 0 {
		lo = 0
	}
	win := strings.ToLower(sent[lo:idx])
	for _, kw := range briefCallbackKeywords {
		if strings.Contains(win, kw) {
			return true
		}
	}
	return false
}

// isNegatedBriefContext 判断分句里位于 idx 处的 URL/IP 之前是否出现否定或排除指令
// （如「禁止访问」「不要碰」「排除」「out of scope」）。命中一律拒收，避免把禁区写进 seed scope。
func isNegatedBriefContext(sent string, idx int) bool {
	prefix := strings.ToLower(sent[:idx])
	for _, kw := range briefNegationKeywords {
		if strings.Contains(prefix, kw) {
			return true
		}
	}
	return false
}

// ExtractBriefHosts 返回任务书文本里显式指令地址的 host 列表(小写、去端口、
// 去重、按出现顺序)。提取不出返回 nil。
func ExtractBriefHosts(text string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		h = normalizeHost(h)
		if h == "" || seen[h] || briefPlaceholderHost(h) {
			return
		}
		if ip := net.ParseIP(h); ip != nil {
			if !briefUsableIP(ip) {
				return
			}
		}
		seen[h] = true
		out = append(out, h)
	}

	// 按分句切分（英文句号不切，避免拆烂 IPv4/域名），每分句内同时做否定与回连上下文过滤。
	clauses := strings.FieldsFunc(text, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ';' || r == '。' || r == '；' || r == '!' || r == '！' || r == '?' || r == '？' || r == '，' || r == ','
	})

	for _, sent := range clauses {
		// 1) 完整 http(s) URL 的 host：URL 字面值本身就是访问指令，但仍须排除
		//    否定/排除语境与操作员回调语境。
		for _, idx := range reBriefURL.FindAllStringIndex(sent, -1) {
			if isNegatedBriefContext(sent, idx[0]) || isCallbackContext(sent, idx[0]) {
				continue
			}
			m := sent[idx[0]:idx[1]]
			for _, piece := range splitShellGlue(m) {
				piece = strings.TrimRight(piece, "。、，,.;:')]>")
				u, err := url.Parse(piece)
				if err != nil || u.Hostname() == "" {
					continue
				}
				h := cleanExtractedHost(u.Hostname())
				if h == "" || strings.ContainsAny(h, "{}$") {
					continue
				}
				add(h)
			}
		}

		// 2) 裸 IP 字面值：仅当同一分句带访问类指令动词，且不在否定/回连语境内。
		if !reBriefDirective.MatchString(sent) {
			continue
		}
		for _, idx := range reBriefIP.FindAllStringIndex(sent, -1) {
			if isNegatedBriefContext(sent, idx[0]) || isCallbackContext(sent, idx[0]) {
				continue
			}
			m := sent[idx[0]:idx[1]]
			host := stripPortMaybe(stripShellGlueEdges(m))
			host = strings.TrimSuffix(host, ".")
			if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && briefUsableIP(ip) {
				add(host)
			}
		}
	}
	return out
}
