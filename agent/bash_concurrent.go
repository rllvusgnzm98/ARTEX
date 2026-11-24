package agent

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

type concurrentBash struct{ actool.CoreTool }

func (t *concurrentBash) IsConcurrencySafe(in json.RawMessage) bool {
	// The classifier below assumes a POSIX shell (bash -c) with bash quoting
	// and a unix command allowlist. On Windows the Bash tool runs through
	// PowerShell, whose parsing, escaping and command names differ, so the
	// classification is unsound there: stay serial (fail safe).
	if runtime.GOOS == "windows" {
		return false
	}
	var input struct {
		Command         string `json:"command"`
		RunInBackground bool   `json:"run_in_background"`
	}
	if json.Unmarshal(in, &input) != nil {
		return false
	}
	// A background launch mutates the task manager (it registers a new job),
	// so a same-turn TaskList/TaskOutput could race ahead of registration.
	// Only plain foreground reads are eligible for concurrency.
	if input.RunInBackground {
		return false
	}
	return bashCommandReadOnly(input.Command)
}

func wrapConcurrentBash(t actool.CoreTool) actool.CoreTool {
	if t.Name() == "Bash" {
		return &concurrentBash{t}
	}
	return t
}

func bashCommandReadOnly(command string) bool {
	return bashCommandInAllowlist(command, true)
}

var (
	rePythonInline     = regexp.MustCompile(`^(?:/usr/bin/|/bin/)?python3?(?:\s+-[A-Za-z]+)*\s+-c\s+`)
	rePythonHeredoc    = regexp.MustCompile(`^(?:/usr/bin/|/bin/)?python3?(?:\s+-[A-Za-z]+)*(?:\s+-)?\s+<<-?\s*'([A-Za-z_][A-Za-z0-9_]*)'\s*(?:\r?\n|$)`)
	rePythonOpenWrite  = regexp.MustCompile(`(?i)open\s*\([^)]*,\s*['"][wax+]`)
	rePythonIPv4       = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	reSedLineRange     = regexp.MustCompile(`^\d+(?:,\d+)?p$`)
	reLocalCdPrefix    = regexp.MustCompile(`^cd\s+[^\n;|&` + "`" + `$<>]+?(?:\s*&&\s*|\s*;\s*|\s*\r?\n\s*)`)
)

// isLocalReadOnlyBash reports whether command is a provably read-only local
// inspection or static analysis command (including multiline `;`/`\n`/`|`/`&&`/`||`
// pipelines, reversing inspection binaries like objdump/readelf/nm/file/xxd, and
// offline read-only python3 analysis), excluding network-facing recon commands.
// Used by stop-loss so local output parsing does not burn the worker's
// target-probe idle budget.
func isLocalReadOnlyBash(command string) bool {
	if isOfflineReadOnlyPython(command) {
		return true
	}
	cleaned := preprocessLocalReadOnlyBash(command)
	segs, ok := splitLocalReadOnlyPipeline(cleaned)
	if !ok || len(segs) == 0 {
		return false
	}
	for _, seg := range segs {
		if !localReadOnlySegmentAllowed(seg) {
			return false
		}
	}
	return true
}

func isOfflineReadOnlyPython(command string) bool {
	trimmed := stripLeadingShellComments(command)
	if trimmed == "" {
		return false
	}
	if loc := reLocalCdPrefix.FindStringIndex(trimmed); loc != nil {
		trimmed = strings.TrimSpace(trimmed[loc[1]:])
	}
	if trimmed == "" {
		return false
	}
	var body string
	if m := rePythonHeredoc.FindStringSubmatchIndex(trimmed); m != nil {
		tag := trimmed[m[2]:m[3]]
		rest := trimmed[m[1]:]
		lines := strings.Split(rest, "\n")
		endIdx := -1
		for i, l := range lines {
			if strings.TrimRight(l, "\r") == tag {
				endIdx = i
				break
			}
		}
		if endIdx < 0 {
			return false
		}
		// Ensure nothing follows the heredoc terminator except comments/whitespace.
		for _, tail := range lines[endIdx+1:] {
			t := strings.TrimSpace(tail)
			if t != "" && !strings.HasPrefix(t, "#") {
				return false
			}
		}
		body = strings.Join(lines[:endIdx], "\n")
	} else if loc := rePythonInline.FindStringIndex(trimmed); loc != nil {
		rest := strings.TrimSpace(trimmed[loc[1]:])
		if len(rest) < 2 || (rest[0] != '\'' && rest[0] != '"') {
			return false
		}
		quote := rest[0]
		i := 1
		for i < len(rest) {
			if quote == '"' && rest[i] == '\\' && i+1 < len(rest) {
				i += 2
				continue
			}
			if rest[i] == quote {
				break
			}
			if quote == '"' && (rest[i] == '`' || (rest[i] == '$' && i+1 < len(rest) && rest[i+1] == '(')) {
				return false
			}
			i++
		}
		if i >= len(rest) || rest[i] != quote {
			return false
		}
		if strings.TrimSpace(rest[i+1:]) != "" {
			return false
		}
		body = rest[1:i]
	} else {
		return false
	}
	lower := strings.ToLower(body)
	for _, forbidden := range []string{
		"socket", "urllib", "requests", "http.client", "httpx", "aiohttp",
		"ftplib", "telnetlib", "paramiko", "pwn", "scapy", "subprocess",
		"os.system", "os.popen", "os.exec", "os.spawn", "pty", "shutil",
		".write_text", ".write_bytes", "://",
	} {
		if strings.Contains(lower, forbidden) {
			return false
		}
	}
	if rePythonOpenWrite.MatchString(body) || rePythonIPv4.MatchString(body) {
		return false
	}
	return true
}

func stripLeadingShellComments(command string) string {
	lines := strings.Split(command, "\n")
	i := 0
	for i < len(lines) {
		t := strings.TrimSpace(lines[i])
		if t == "" || strings.HasPrefix(t, "#") {
			i++
			continue
		}
		break
	}
	return strings.TrimSpace(strings.Join(lines[i:], "\n"))
}

// preprocessLocalReadOnlyBash drops full-line `#` comments and safe stderr
// redirections (`2>/dev/null`, `2>&1`) outside quotes before pipeline splitting.
func preprocessLocalReadOnlyBash(command string) string {
	lines := strings.Split(command, "\n")
	kept := make([]string, 0, len(lines))
	inSingle, inDouble := false, false
	for _, line := range lines {
		if !inSingle && !inDouble {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
		}
		for i := 0; i < len(line); i++ {
			c := line[i]
			if inSingle {
				if c == '\'' {
					inSingle = false
				}
				continue
			}
			if c == '\\' {
				i++
				continue
			}
			if inDouble {
				if c == '"' {
					inDouble = false
				}
				continue
			}
			if c == '\'' {
				inSingle = true
			} else if c == '"' {
				inDouble = true
			}
		}
		kept = append(kept, line)
	}
	joined := strings.Join(kept, "\n")
	return stripSafeStderrRedirects(joined)
}

func stripSafeStderrRedirects(command string) string {
	var b strings.Builder
	b.Grow(len(command))
	var quote byte
	for i := 0; i < len(command); i++ {
		c := command[i]
		if quote == '\'' {
			b.WriteByte(c)
			if c == '\'' {
				quote = 0
			}
			continue
		}
		if c == '\\' && i+1 < len(command) {
			b.WriteByte(c)
			i++
			b.WriteByte(command[i])
			continue
		}
		if quote == '"' {
			b.WriteByte(c)
			if c == '"' {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			b.WriteByte(c)
			continue
		}
		prevBoundary := i == 0 || command[i-1] == ' ' || command[i-1] == '\t' || command[i-1] == '\n' || command[i-1] == ';' || command[i-1] == '|' || command[i-1] == '&'
		if prevBoundary {
			rest := command[i:]
			if strings.HasPrefix(rest, "2>/dev/null") && isRedirectSuffixBoundary(rest, len("2>/dev/null")) {
				b.WriteByte(' ')
				i += len("2>/dev/null") - 1
				continue
			}
			if strings.HasPrefix(rest, "2>&1") && isRedirectSuffixBoundary(rest, len("2>&1")) {
				b.WriteByte(' ')
				i += len("2>&1") - 1
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

func isRedirectSuffixBoundary(s string, n int) bool {
	if len(s) == n {
		return true
	}
	switch s[n] {
	case ' ', '\t', '\r', '\n', ';', '|', '&':
		return true
	}
	return false
}

func splitLocalReadOnlyPipeline(command string) ([]string, bool) {
	if strings.TrimSpace(command) == "" {
		return nil, false
	}
	var segs []string
	var cur strings.Builder
	var quote byte
	needNext := false
	flush := func(requireNonEmpty bool) bool {
		s := strings.TrimSpace(cur.String())
		cur.Reset()
		if s == "" {
			return !requireNonEmpty
		}
		segs = append(segs, s)
		needNext = false
		return true
	}
	for i := 0; i < len(command); i++ {
		c := command[i]
		if c == 0 {
			return nil, false
		}
		if quote == '\'' {
			cur.WriteByte(c)
			if c == '\'' {
				quote = 0
			}
			continue
		}
		if c == '\\' {
			if i+1 == len(command) || command[i+1] == '\n' {
				return nil, false
			}
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
		case '<', '>', '`':
			return nil, false
		case '$':
			if i+1 < len(command) && command[i+1] == '(' {
				return nil, false
			}
			cur.WriteByte(c)
		case '|':
			if i+1 < len(command) && command[i+1] == '&' {
				return nil, false
			}
			if !flush(true) {
				return nil, false
			}
			if i+1 < len(command) && command[i+1] == '|' {
				i++
			}
			needNext = true
		case '&':
			if i+1 < len(command) && command[i+1] == '&' {
				if !flush(true) {
					return nil, false
				}
				i++
				needNext = true
				continue
			}
			return nil, false
		case ';', '\n', '\r':
			if !flush(needNext) {
				return nil, false
			}
		default:
			cur.WriteByte(c)
		}
	}
	if quote != 0 || !flush(needNext) || len(segs) == 0 {
		return nil, false
	}
	return segs, true
}

func localReadOnlySegmentAllowed(seg string) bool {
	if bashCommandInAllowlist(seg, false) {
		return true
	}
	words, ok := bashInspectionWords(seg)
	if !ok || len(words) == 0 || words[0].glob || strings.Contains(words[0].text, "=") {
		return false
	}
	name := filepath.Base(words[0].text)
	switch name {
	case "cd", "objdump", "readelf", "nm", "size", "jq", "diff", "cmp":
		return true
	case "file":
		for _, w := range words[1:] {
			arg := w.text
			if arg == "-C" || arg == "--compile" || (strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(arg, "C")) {
				return false
			}
		}
		return true
	case "xxd":
		for _, w := range words[1:] {
			arg := w.text
			if arg == "-r" || arg == "-revert" || arg == "--revert" || (strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(arg, "r")) {
				return false
			}
		}
		return true
	case "sort":
		for _, w := range words[1:] {
			arg := w.text
			if arg == "-o" || strings.HasPrefix(arg, "-o") || strings.HasPrefix(arg, "--output") {
				return false
			}
		}
		return true
	case "sed":
		quiet := false
		hasRange := false
		for _, w := range words[1:] {
			arg := w.text
			if arg == "-n" || arg == "--quiet" || arg == "--silent" {
				quiet = true
				continue
			}
			if strings.HasPrefix(arg, "-") {
				return false
			}
			if !hasRange && reSedLineRange.MatchString(arg) {
				hasRange = true
			}
		}
		return quiet && hasRange
	default:
		return bashAllowlistWordsSafe(name, words[1:], false)
	}
}

func bashCommandInAllowlist(command string, allowNetworkRecon bool) bool {
	words, ok := bashInspectionWords(command)
	if !ok || len(words) == 0 || strings.ContainsAny(words[0].text, "/=") {
		return false
	}
	return bashAllowlistWordsSafe(words[0].text, words[1:], allowNetworkRecon)
}

func bashAllowlistWordsSafe(name string, args []bashInspectionWord, allowNetworkRecon bool) bool {
	switch name {
	case "cat", "head", "tail", "ls", "dir", "vdir", "stat", "wc",
		"grep", "egrep", "fgrep", "rg", "find", "cut", "tr", "comm", "join", "paste",
		"nl", "tac", "rev", "fold", "fmt", "column", "basename", "dirname", "realpath",
		"readlink", "pwd", "echo", "printf", "whoami", "id", "uname", "arch", "uptime",
		"printenv", "which", "type", "md5sum", "sha1sum", "sha256sum", "sha512sum",
		"cksum", "b2sum", "od", "hexdump", "strings", "du", "df", "free", "lsblk",
		"lscpu", "ps", "seq", "true", "false", "locale", "tty":
	case "netstat", "dig", "host", "nslookup", "whois", "getent":
		if !allowNetworkRecon {
			return false
		}
	default:
		return false
	}
	for _, word := range args {
		arg := word.text
		switch name {
		case "find", "rg", "head", "tail":
			// A glob must not expand into an action/option supplied by a filename.
			if word.glob && len(arg) > 0 && strings.ContainsAny(arg[:1], "-*?[") {
				return false
			}
		}
		switch name {
		case "find":
			switch arg {
			case "-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprintf", "-fprint0", "-fls":
				return false
			}
		case "rg":
			if strings.HasPrefix(arg, "--pre") || strings.HasPrefix(arg, "--hostname-bin") {
				return false
			}
		case "head", "tail":
			if strings.HasPrefix(arg, "--") {
				flag, _, _ := strings.Cut(arg, "=")
				if len(flag) > 2 && strings.HasPrefix("--follow", flag) {
					return false
				}
			} else if strings.HasPrefix(arg, "-") && strings.ContainsAny(arg, "fF") {
				return false
			}
		}
	}
	return true
}

type bashInspectionWord struct {
	text string
	glob bool
}

func bashInspectionWords(command string) ([]bashInspectionWord, bool) {
	if strings.TrimSpace(command) == "" {
		return nil, false
	}
	var words []bashInspectionWord
	var word strings.Builder
	var quote byte
	active, glob := false, false
	flush := func() {
		if active {
			words = append(words, bashInspectionWord{word.String(), glob})
			word.Reset()
			active, glob = false, false
		}
	}
	for i := 0; i < len(command); i++ {
		c := command[i]
		if c == 0 {
			return nil, false
		}
		if quote == '\'' {
			if c == '\'' {
				quote = 0
			} else {
				word.WriteByte(c)
			}
			continue
		}
		if c == '\\' {
			if i+1 == len(command) || command[i+1] == '\n' {
				return nil, false
			}
			if quote == '"' && !strings.ContainsRune("$`\"\\", rune(command[i+1])) {
				word.WriteByte(c)
				continue
			}
			i++
			word.WriteByte(command[i])
			active = true
			continue
		}
		if quote == '"' {
			switch c {
			case '"':
				quote = 0
			case '$', '`':
				return nil, false
			default:
				word.WriteByte(c)
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			active = true
		case ' ', '\t':
			flush()
		case '|', '&', ';', '<', '>', '`', '(', ')', '{', '}', '$', '\n':
			return nil, false
		default:
			word.WriteByte(c)
			active = true
			glob = glob || strings.ContainsRune("*?[", rune(c))
		}
	}
	if quote != 0 {
		return nil, false
	}
	flush()
	return words, true
}
