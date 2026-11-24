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
	"xfreerdp": true,
	"ffuf":     true, "feroxbuster": true, "gobuster": true, "sqlmap": true,
	"nuclei": true, "whatweb": true, "commix": true, "katana": true, "nxc": true,
	"impacket-secretsdump": true, "impacket-psexec": true,
	"impacket-wmiexec": true, "impacket-smbclient": true,
	"impacket-getuserspns": true,
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
}

// valueFlags take a non-host value as the next token; that token must not be
// mistaken for a target. 保守取向:宁缺勿滥。
var valueFlags = map[string]bool{
	"-p": true, "-o": true, "-oA": true, "-oX": true, "-oN": true, "-oG": true,
	"-iL": true, "-i": true, "-e": true, "-w": true, "-t": true, "-c": true,
	"-H": true, "-A": true, "-U": true, "-d": true, "-x": true, "-u": true,
	"-F": true, "-b": true, "-m": true, "-l": true, "-L": true, "-P": true,
	"-C": true, "-O": true, "-T": true, "-D": true, "-K": true,
	"--data": true, "--data-binary": true, "--data-raw": true, "--data-urlencode": true,
	"--header": true, "--proxy": true, "--user-agent": true,
	"--connect-timeout": true, "--max-time": true, "--output": true,
	"--config": true, "--cookie": true, "--cookie-jar": true, "--upload-file": true,
	"--cacert": true, "--cert": true, "--key": true,
	"--top-ports": true, "--min-rate": true, "--max-rate": true,
}

var (
	reScheme = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s'"<>|\\^` + "`" + `]+`)
	// 主机名:至少一段点分且以字母 TLD 结尾(file.txt 这类误判由 valueFlags 与扩展名黑名单兜住)。
	reHostName     = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]*\.)+[a-z]{2,}$`)
	reSegmentSplit = regexp.MustCompile(`[|;&\r\n]+`)
	reTokenSplit   = regexp.MustCompile(`\s+`)
)

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

	// Pass 1: URLs anywhere in the command.
	for _, raw := range reScheme.FindAllString(command, -1) {
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			add(u.Hostname())
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
				addHostCandidate(add, tok)
				takeHost = false
				continue
			}
			base := strings.ToLower(baseOf(tok))
			if isShellKeyword(base) {
				curTool = ""
				continue
			}
			if hostTools[base] {
				curTool = base
				continue
			}
			if curTool != "" {
				if strings.HasPrefix(tok, "-") {
					name, inline := splitFlag(tok)
					if hostValueFlags[curTool][name] {
						if inline != "" {
							addHostCandidate(add, inline)
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
				addHostCandidate(add, tok)
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

// parseBareIP returns the normalized IP if tok is an IP literal or ip:port.
func parseBareIP(tok string) string {
	if host, _, err := net.SplitHostPort(tok); err == nil {
		tok = host
	}
	tok = strings.Trim(tok, "[]")
	if net.ParseIP(tok) != nil {
		return tok
	}
	return ""
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

// addHostCandidate 按既有风格收下一条可能的目标:URL host、user@host 的 host、
// 裸 IP 或点分主机名。CIDR 字面量故意不提取(与 nmap 192.168.1.0/24 既有语义一致)。
func addHostCandidate(add func(string), tok string) {
	tok = strings.Trim(tok, `"'`)
	if tok == "" {
		return
	}
	if at := strings.LastIndex(tok, "@"); at >= 0 {
		tok = tok[at+1:] // ssh / impacket user@host
	}
	if strings.Contains(tok, "://") {
		if u, err := url.Parse(tok); err == nil && u.Hostname() != "" {
			add(u.Hostname())
		}
		return
	}
	if isCIDRLiteral(tok) {
		return
	}
	if ip := parseBareIP(tok); ip != "" {
		add(ip)
		return
	}
	host := stripPortMaybe(tok)
	if reHostName.MatchString(host) && !hasNonTLDFileExt(host) {
		add(tok)
	}
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
	".pyc": true,
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
