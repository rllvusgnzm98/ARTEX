package guard

import (
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// hostTools are the common interaction tools whose positional argument is a
// target host / host:port / IP literal. Keys are lowercase; lookup uses
// strings.ToLower so catalog names like impacket-GetUserSPNs still match.
//
// 含 ShellHintSeeds(#9) 里会带目标的 CLI:ffuf/feroxbuster/gobuster/sqlmap/
// nuclei/whatweb/commix/katana/nxc/impacket-*。hashcat/john/jq 不带目标,不收录。
var hostTools = map[string]bool{
	"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true,
	"nmap": true, "ssh": true, "ping": true, "telnet": true, "dig": true,
	"host": true, "nslookup": true, "masscan": true, "httpx": true,
	"hydra": true, "smbclient": true, "rpcclient": true, "rdesktop": true,
	"xfreerdp": true, "evil-winrm": true,
	"ffuf": true, "feroxbuster": true, "gobuster": true, "sqlmap": true,
	"nuclei": true, "whatweb": true, "commix": true, "katana": true, "nxc": true,
	"naabu": true, "fscan": true, "gogo": true,
	"impacket-secretsdump": true, "impacket-psexec": true,
	"impacket-wmiexec": true, "impacket-smbclient": true,
	"impacket-getuserspns": true,
}

func isHostTool(base string) bool {
	return hostTools[base] || strings.HasPrefix(base, "impacket-")
}

func isSingleTargetTool(tool string) bool {
	switch tool {
	case "ssh", "smbclient", "rpcclient", "evil-winrm", "nxc":
		return true
	}
	return strings.HasPrefix(tool, "impacket-")
}

// hostValueFlags 是按工具列出的「下一个参数(或 --flag=value)才是目标」的开关。
// 只覆盖这些 CLI 文档里常用的目标开关,不把 -l/-w/-t 等文件或模板参数当 host。
// 同一开关在别的工具里可能是用户名(curl/nxc -u),所以必须按当前工具查表,
// 不能全局改变 valueFlags 的跳过语义。
var hostValueFlags = map[string]map[string]bool{
	"ffuf":        {"-u": true, "--url": true},
	"feroxbuster": {"-u": true, "--url": true},
	"gobuster":    {"-u": true, "--url": true, "-d": true, "--domain": true},
	"sqlmap":      {"-u": true, "--url": true},
	"nuclei":      {"-u": true, "--target": true, "-target": true},
	"commix":      {"-u": true, "--url": true},
	"katana":      {"-u": true, "--url": true},
	"naabu":       {"-host": true},
	"fscan":       {"-h": true},
	"gogo":        {"-i": true},
	"ssh":         {"-J": true},
	"evil-winrm":  {"-i": true},
}

// valueFlags take a non-host value as the next token; that token must not be
// mistaken for a target. 保守取向:宁缺勿滥。
var valueFlags = map[string]bool{
	"-p": true, "-o": true, "-oA": true, "-oX": true, "-oN": true, "-oG": true,
	"-iL": true, "-i": true, "-e": true, "-w": true, "-t": true, "-c": true,
	"-H": true, "-A": true, "-U": true, "-d": true, "-x": true, "-u": true,
	"-F": true, "-b": true, "-m": true, "-l": true, "-L": true, "-P": true,
	"-C": true, "-O": true, "-T": true, "-D": true, "-K": true,
	"-R": true, "-S": true, "-W": true, "-E": true, "-I": true, "-Q": true,
	"--data": true, "--data-binary": true, "--data-raw": true, "--data-urlencode": true,
	"--header": true, "--proxy": true, "--user-agent": true,
	"--connect-timeout": true, "--max-time": true, "--output": true,
	"--config": true, "--cookie": true, "--cookie-jar": true, "--upload-file": true,
	"--cacert": true, "--cert": true, "--key": true,
	"--top-ports": true, "--min-rate": true, "--max-rate": true,
}

var (
	reScheme = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s'"<>|\\^` + "`" + `]+`)
	// reXMLNSAttrPrefix matches XML/SOAP namespace attribute prefixes right before a URI:
	// e.g. xmlns=", xmlns:soapenv=', xmlns:wsa=\".
	reXMLNSAttrPrefix = regexp.MustCompile(`(?i)\bxmlns(?::[a-z0-9._-]+)?\s*=\s*\\?["']?$`)
	// 主机名:至少一段点分且以字母 TLD 结尾(file.txt 这类误判由 valueFlags 与扩展名黑名单兜住)。
	reHostName     = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]*\.)+[a-z]{2,}$`)
	reSegmentSplit = regexp.MustCompile(`[|;&\r\n]+`)
	reTokenSplit   = regexp.MustCompile(`\s+`)
)

// xmlSchemaHosts are standard XML/SOAP/Spring/WebLogic namespace schema hosts
// that appear inside payload bodies rather than as network targets.
var xmlSchemaHosts = map[string]bool{
	"www.w3.org":              true,
	"schemas.xmlsoap.org":     true,
	"schemas.microsoft.com":   true,
	"www.bea.com":             true,
	"www.springframework.org": true,
}

// shellGlueRunes 是 shell 语法/分隔符字符:命令行里它们从不属于 host,属于
// 粘连的语法残留(如 `curl http://a;,`、子shell `)`、命令替换边界)。
// 注意保守:
//   - 冒号不在内(端口与 IPv6 语义,端口由 stripPortMaybe 处理);
//   - `{}` 不在内:`${var}`/`{{template}}` 可能出现在 URL userinfo/路径里,
//     拆开会丢 host;变量残留由 stripShellVarSuffix 的既有语义处理;
//   - `<>&|` 不在内:重定向/管道已由 reSegmentSplit 与 redirect 跳过逻辑处理,
//     且 reScheme 本身不匹配它们。
//
// 逗号恒拆:host:port 列表(ffuf -u a.com,b.com)正是要拆的场景;合法 host 不含逗号。
const shellGlueRunes = ";,()"

// splitShellGlue 把粘连了 shell 语法字符的串按 glue 边界拆开,丢弃空段。
func splitShellGlue(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return strings.ContainsRune(shellGlueRunes, r)
	})
}

// stripShellGlueEdges 剥掉 host 首尾粘连的 shell 语法字符(trailing `;`/`)`/`,`
// 与 leading `(` 等)。IP/主机名匹配之前先剥,否则 `10.0.100.58;,` 整串永远不命中。
func stripShellGlueEdges(s string) string {
	return strings.Trim(s, shellGlueRunes)
}

func isXMLNamespaceContext(prefix string) bool {
	return reXMLNSAttrPrefix.MatchString(prefix)
}

func isXMLNamespaceToken(tok string) bool {
	low := strings.ToLower(tok)
	return strings.HasPrefix(low, "xmlns=") || strings.HasPrefix(low, "xmlns:")
}

func isXMLSchemaHost(h string) bool {
	return xmlSchemaHosts[strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))]
}

// ExtractHosts extracts likely interaction targets from a shell command line:
// hosts of URLs (scheme://...), host:port / IP literals following common tool
// names, and standalone IP literals. 保守取向:提取不出 = 无目标(不拦截)。
// Returned hosts are lowercased, port-stripped, deduplicated, in first-seen order.
func ExtractHosts(command string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(h string) {
		h = normalizeHost(h)
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		out = append(out, h)
	}

	// Pass 1: URLs anywhere in the command (skipping XML/SOAP xmlns namespace URIs).
	// 先按 shell glue(`;,()` 等)拆开粘连串:reScheme 不把这些字符排除在外,
	// 像 `curl http://a;,` 或 `http://a,http://b` 会整体被 URL 正则吞掉,
	// 导致 Hostname() 带出尾标点、scope 永不命中。
	for _, idx := range reScheme.FindAllStringIndex(command, -1) {
		if isXMLNamespaceContext(command[:idx[0]]) {
			continue
		}
		for _, piece := range splitShellGlue(command[idx[0]:idx[1]]) {
			if h := extractURLHost(piece); h != "" {
				add(h)
			}
		}
	}

	// Pass 2: segment-scoped token scan — reset tool context on every pipe /
	// chain / newline so downstream commands (grep, python3, cat) do not inherit
	// an upstream hostTool, and skip redirection targets.
	for _, seg := range reSegmentSplit.Split(command, -1) {
		curTool := "" // 当前 hostTools 工具名(小写);空表示不在工具参数位
		skipNext := false
		takeHost := false // 上一个词是当前工具的目标开关,本词按 host 收
		skipRedirect := false
		for _, tok := range reTokenSplit.Split(seg, -1) {
			tok = strings.Trim(tok, `"'`)
			if tok == "" {
				continue
			}
			if skipRedirect {
				skipRedirect = false
				continue
			}
			if isRedirectOpToken(tok) {
				skipRedirect = true
				continue
			}
			if startsWithRedirectOp(tok) {
				continue
			}
			if skipNext {
				skipNext = false
				takeHost = false
				continue
			}
			if takeHost {
				matched := addHostCandidate(add, tok)
				takeHost = false
				if matched && curTool == "evil-winrm" {
					curTool = ""
				}
				continue
			}
			base := strings.ToLower(baseOf(tok))
			if isShellKeyword(base) {
				curTool = ""
				continue
			}
			if isHostTool(base) {
				curTool = base
				continue
			}
			if curTool != "" {
				if strings.HasPrefix(tok, "-") {
					name, inline := splitFlag(tok)
					if hostValueFlags[curTool][name] {
						if inline != "" {
							if addHostCandidate(add, inline) && curTool == "evil-winrm" {
								curTool = ""
							}
						} else {
							takeHost = true
						}
						continue
					}
					if valueFlags[tok] {
						skipNext = true
					}
					continue
				}
				matched := addHostCandidate(add, tok)
				// Single-target remote tools take one destination; subsequent tokens
				// are remote commands or share/module arguments rather than extra hosts.
				if curTool == "ssh" || (matched && isSingleTargetTool(curTool)) {
					curTool = ""
				}
				continue
			}
			// 非工具参数位置:只收独立 IP 字面量(裸主机名歧义太大,宁缺勿滥)。
			if ip := parseBareIP(tok); ip != "" {
				add(ip)
			}
		}
	}
	return out
}

func isRedirectOpToken(tok string) bool {
	switch tok {
	case ">", ">>", "<", "1>", "1>>", "2>", "2>>", "&>", "&>>":
		return true
	default:
		return false
	}
}

func startsWithRedirectOp(tok string) bool {
	for _, p := range []string{">>", ">", "<", "1>>", "1>", "2>>", "2>", "&>>", "&>"} {
		if strings.HasPrefix(tok, p) {
			return true
		}
	}
	return false
}

func isShellKeyword(tok string) bool {
	switch tok {
	case "sudo", "doas", "env", "time", "nice", "xargs":
		return true
	}
	return false
}

func baseOf(tok string) string {
	if j := strings.LastIndex(tok, "/"); j >= 0 {
		return tok[j+1:]
	}
	return tok
}

func stripShellVarSuffix(s string) string {
	idx := strings.IndexByte(s, '$')
	if idx < 0 {
		if strings.IndexAny(s, "{}") >= 0 {
			return ""
		}
		return s
	}
	s = s[:idx]
	if strings.IndexAny(s, "{}") >= 0 {
		return ""
	}
	s = strings.TrimRight(s, ".")
	if !strings.HasSuffix(s, "::") {
		s = strings.TrimRight(s, ":")
	}
	return s
}

func isNonNetworkScheme(raw string) bool {
	idx := strings.Index(raw, "://")
	if idx <= 0 {
		return false
	}
	scheme := strings.ToLower(raw[:idx])
	if strings.HasPrefix(scheme, "compress.") {
		return true
	}
	switch scheme {
	case "file", "php", "phar", "data", "zip", "rar", "ogg", "glob", "expect",
		"javascript", "mailto", "about", "blob", "chrome", "view-source":
		return true
	}
	return false
}

func cleanExtractedHost(rawHost string) string {
	h := strings.Trim(stripShellVarSuffix(rawHost), "[]")
	// URL 的 Hostname() 是宽松解析:`http://10.0.100.58;,` 会带出 `;,`。
	// 剥掉首尾 shell glue,scope 匹配才能命中已登记的 host。
	h = stripShellGlueEdges(h)
	if h == "" || h == "." || h == ".." {
		return ""
	}
	return h
}

func extractURLHost(raw string) string {
	if isNonNetworkScheme(raw) {
		return ""
	}
	if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
		h := cleanExtractedHost(u.Hostname())
		if isXMLSchemaHost(h) {
			return ""
		}
		return h
	}
	if idx := strings.IndexByte(raw, '$'); idx >= 0 {
		if u, err := url.Parse(raw[:idx]); err == nil && u.Hostname() != "" {
			h := cleanExtractedHost(u.Hostname())
			if isXMLSchemaHost(h) {
				return ""
			}
			return h
		}
	}
	return ""
}

// parseBareIP returns the normalized IP if tok is an IP literal or ip:port,
// filtering netmask/broadcast/unspecified addresses (255.*.*.*, 0.0.0.0, ::).
func parseBareIP(tok string) string {
	tok = stripShellVarSuffix(tok)
	// 独立 IP 路径不经过 addHostCandidate,`echo 10.0.0.58),` 这类粘连要在这里剥。
	tok = stripShellGlueEdges(tok)
	if tok == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(tok); err == nil {
		tok = host
	}
	tok = strings.Trim(tok, "[]")
	ip := net.ParseIP(tok)
	if ip == nil {
		return ""
	}
	if ip.IsUnspecified() {
		return ""
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 255 {
		return ""
	}
	return tok
}

// stripPortMaybe drops a trailing :<numeric-port> from host:port (best effort).
func stripPortMaybe(tok string) string {
	if host, port, err := net.SplitHostPort(tok); err == nil {
		if _, err := strconv.Atoi(port); err == nil {
			return host
		}
	}
	return tok
}

// addHostCandidate 按既有风格收下一条可能的目标:URL host、UNC //host/share、
// user@host 的 host、裸 IP 或点分主机名。CIDR 字面量故意不提取(与 nmap 192.168.1.0/24
// 既有语义一致)。返回值表示该 token 是否匹配到了目标(含 CIDR)，用于单目标工具重置上下文。
func addHostCandidate(add func(string), tok string) bool {
	tok = strings.Trim(tok, `"'`)
	// 粘连串按 shell glue 拆开逐个收:`nmap 10.0.0.1,10.0.0.2`、
	// 命令替换/子shell 残留的 `(10.0.0.1)`、host 列表 `a.com,b.com`。
	// 任一片段变化才递归,避免无限下降。
	if strings.IndexAny(tok, shellGlueRunes) >= 0 {
		matched := false
		for _, frag := range splitShellGlue(tok) {
			if frag != tok && addHostCandidate(add, frag) {
				matched = true
			}
		}
		return matched
	}
	if tok == "" || isXMLNamespaceToken(tok) {
		return false
	}
	if at := strings.LastIndex(tok, "@"); at >= 0 {
		tok = tok[at+1:] // ssh / impacket user@host
	}
	if strings.Contains(tok, "://") {
		if h := extractURLHost(tok); h != "" {
			add(h)
			return true
		}
		return false
	}
	if strings.HasPrefix(tok, "//") || strings.HasPrefix(tok, `\\`) {
		rest := strings.TrimLeft(tok, `/\`)
		if sep := strings.IndexAny(rest, `/\`); sep > 0 {
			rest = rest[:sep]
		}
		tok = rest
	}
	if isCIDRLiteral(tok) {
		return true
	}
	tok = stripShellVarSuffix(tok)
	if tok == "" {
		return false
	}
	if ip := parseBareIP(tok); ip != "" {
		add(ip)
		return true
	}
	host := stripPortMaybe(tok)
	if reHostName.MatchString(host) && !hasNonTLDFileExt(host) {
		add(tok)
		return true
	}
	return false
}

var nonTLDFileExts = map[string]bool{
	".txt": true, ".html": true, ".htm": true, ".json": true, ".jsonl": true,
	".js": true, ".mjs": true, ".cjs": true, ".yaml": true, ".yml": true,
	".xml": true, ".csv": true, ".tsv": true, ".log": true, ".sql": true,
	".sqlite": true, ".db": true, ".pdf": true, ".tar": true, ".gz": true,
	".tgz": true, ".bz2": true, ".xz": true, ".7z": true, ".rar": true,
	".pem": true, ".crt": true, ".cer": true, ".key": true, ".bak": true,
	".tmp": true, ".swp": true, ".asm": true, ".elf": true, ".bin": true,
	".php": true, ".jsp": true, ".asp": true, ".aspx": true,
	".wordlist": true, ".dic": true, ".lst": true, ".md": true,
	".ini": true, ".conf": true, ".cfg": true, ".toml": true,
	".wasm": true, ".apk": true, ".ipa": true, ".jar": true, ".war": true,
	".pyc":  true,
	".save": true, ".hiv": true, ".parse": true, ".dmp": true, ".reg": true,
	".kirbi": true, ".ccache": true, ".py": true, ".ps1": true, ".exe": true,
	".dll": true, ".class": true,
}

func hasNonTLDFileExt(host string) bool {
	ext := strings.ToLower(filepath.Ext(host))
	return nonTLDFileExts[ext]
}

// splitFlag 拆出 -u/--url 与可选的 =value;不认识的粘连短选项保持原样当 name。
func splitFlag(tok string) (name, value string) {
	if i := strings.Index(tok, "="); i > 0 && strings.HasPrefix(tok, "-") {
		return tok[:i], tok[i+1:]
	}
	return tok, ""
}

func isCIDRLiteral(tok string) bool {
	if host, port, err := net.SplitHostPort(tok); err == nil {
		if _, err := strconv.Atoi(port); err == nil {
			tok = host
		}
	}
	_, _, err := net.ParseCIDR(tok)
	return err == nil
}
