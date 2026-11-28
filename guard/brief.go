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

// isCallbackContextIP 判断分句里位于 idx 处的 IP 是否落在「本机/攻击机/回连/
// 监听」等说明词的邻近窗口内(向前 16 字节)——这类 IP 是操作员侧地址,不是任务目标。
func isCallbackContextIP(sent string, idx int) bool {
	lo := idx - 16
	if lo < 0 {
		lo = 0
	}
	win := strings.ToLower(sent[lo:idx])
	for _, kw := range []string{"本机", "攻击机", "回连", "监听", "callback", "lhost", "reverse"} {
		if strings.Contains(win, kw) {
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

	// 1) 完整 http(s) URL 的 host:URL 字面值本身就是访问指令。
	for _, m := range reBriefURL.FindAllString(text, -1) {
		// 模板/变量残留({{x}}、${x})与粘连尾标点按 shell glue 拆开;
		// 剥完如果 host 还含 {} 或 $ 说明 host 本身就是模板,放弃。
		for _, piece := range splitShellGlue(m) {
			// 任务书是中文文本,URL 尾部常粘着句读(。/、/))——剥离再解析。
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

	// 2) 裸 IP 字面值:仅当同一分句(按换行/分号/中英文逗号与句读切)带访问类指令动词。
	// 英文句号不在切分符内——IPv4 字面值本身由点组成,切开会把 10.0.0.x 拆烂。
	// URL 里已收的 IP 靠 seen 去重。
	for _, sent := range strings.FieldsFunc(text, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ';' || r == '。' || r == '；' || r == '!' || r == '！' || r == '?' || r == '？' || r == '，' || r == ','
	}) {
		if !reBriefDirective.MatchString(sent) {
			continue
		}
		for _, idx := range reBriefIP.FindAllStringIndex(sent, -1) {
			m := sent[idx[0]:idx[1]]
			host := stripPortMaybe(stripShellGlueEdges(m))
			host = strings.TrimSuffix(host, ".")
			// 「本机/攻击机/回连地址 x.x.x.x」是操作员侧地址,不是目标。
			if isCallbackContextIP(sent, idx[0]) {
				continue
			}
			if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && briefUsableIP(ip) {
				add(host)
			}
		}
	}
	return out
}
