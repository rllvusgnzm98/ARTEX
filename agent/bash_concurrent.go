package agent

import (
	"encoding/json"
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
	words, ok := bashInspectionWords(command)
	if !ok || len(words) == 0 || strings.ContainsAny(words[0].text, "/=") {
		return false
	}
	name := words[0].text
	switch name {
	case "cat", "head", "tail", "ls", "dir", "vdir", "stat", "wc",
		"grep", "egrep", "fgrep", "rg", "find", "cut", "tr", "comm", "join", "paste",
		"nl", "tac", "rev", "fold", "fmt", "column", "basename", "dirname", "realpath",
		"readlink", "pwd", "echo", "printf", "whoami", "id", "uname", "arch", "uptime",
		"printenv", "which", "type", "md5sum", "sha1sum", "sha256sum", "sha512sum",
		"cksum", "b2sum", "od", "hexdump", "strings", "du", "df", "free", "lsblk",
		"lscpu", "ps", "netstat", "dig", "host", "nslookup", "whois", "getent",
		"seq", "true", "false", "locale", "tty":
	default:
		return false
	}
	for _, word := range words[1:] {
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
