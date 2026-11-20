package server

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// Hackbots Toolkit 落地的技能不得再指向外部 agent、固定 VPS 或某台开发机的家目录。
func TestToolkitSkillsDecoupled(t *testing.T) {
	root := repoRoot(t)
	skills := []string{
		"js-endpoint-extraction",
		"lazy-chunk-downloader",
		"jshero",
		"content-discovery-wordlist",
		"api-surface-recon",
		"api-fingerprint-caido",
	}
	forbidden := []string{
		"codex",
		"claude",
		"subagent_type",
		"agent tool",
		"workflow(",
		".codex",
		".claude",
		"/users/",
		`c:\users\`,
		"vps_handshake",
		"207.244.244.11",
		"/jshero ",
	}
	for _, name := range skills {
		dir := filepath.Join(root, "skills", name)
		data, err := os.ReadFile(filepath.Join(dir, "SKILL.md"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		desc := frontmatterDescription(t, name, data)
		if n := utf8.RuneCountInString(desc); n > 350 {
			t.Fatalf("%s: description 长度 %d > 350", name, n)
		}
		checkToolkitSkillDir(t, name, dir, forbidden)
	}
	raw, err := os.ReadFile(filepath.Join(root, "skills", "jshero", "scripts", "secrets_patterns.json"))
	if err != nil {
		t.Fatal(err)
	}
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("secrets_patterns.json: %v", err)
	}
	if parsed == nil {
		t.Fatal("secrets_patterns.json 解析结果为空")
	}
}

func frontmatterDescription(t *testing.T, name string, data []byte) string {
	t.Helper()
	text := strings.TrimPrefix(string(data), "\uFEFF")
	lines := strings.Split(text, "\n")
	if len(lines) < 3 || lines[0] != "---" {
		t.Fatalf("%s: frontmatter 缺失", name)
	}
	for _, ln := range lines[1:] {
		if ln == "---" {
			break
		}
		key, val, ok := strings.Cut(ln, ":")
		if ok && strings.TrimSpace(key) == "description" {
			return strings.Trim(strings.TrimSpace(val), `"'`)
		}
	}
	t.Fatalf("%s: 无 description", name)
	return ""
}

func checkToolkitSkillDir(t *testing.T, name, dir string, forbidden []string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		switch strings.ToLower(filepath.Ext(path)) {
		case ".py", ".js", ".json":
			if bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}) {
				t.Errorf("%s/%s: 含 UTF-8 BOM", name, rel)
			}
			if bytes.Contains(b, []byte{'\r'}) {
				t.Errorf("%s/%s: 必须是 LF", name, rel)
			}
		}
		low := strings.ToLower(string(b))
		for _, needle := range forbidden {
			if strings.Contains(low, needle) {
				t.Errorf("%s/%s: 含禁止字符串 %q", name, rel, needle)
			}
		}
		for _, m := range skillDirRef.FindAllSubmatch(b, -1) {
			relPath := string(m[1])
			full := filepath.Join(dir, filepath.FromSlash(relPath))
			if _, err := os.Stat(full); err != nil {
				t.Errorf("%s: ${SKILL_DIR}/%s 不存在", name, relPath)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

var skillDirRef = regexp.MustCompile(`\$\{SKILL_DIR\}/([^ \t\r\n` + "`" + `"'()\[\]{}<>|*，。；：、]+)`)
