package server

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/skill"
)

// 内置 skills/ 的 frontmatter 必须能被 norma 的 LoadDir 解析。
// 坏头部不会让 LoadDir 返回 error（它会跳过解析失败的字段），但名字或描述
// 一旦丢了，这个技能就不会出现在 agent 的可用列表里，表现像整库消失。
func TestSkillsFormat(t *testing.T) {
	root := repoRoot(t)
	skillsDir := filepath.Join(root, "skills")
	entries, err := os.ReadDir(skillsDir)
	if err != nil {
		t.Fatal(err)
	}
	knownKeys := map[string]bool{
		"name": true, "description": true, "license": true, "compatibility": true,
		"whenToUse": true, "when_to_use": true, "mcps": true, "mcp": true,
	}
	mcpNames := seededMCPNames(t, root)
	var dirs []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		mdPath := filepath.Join(skillsDir, e.Name(), "SKILL.md")
		if _, err := os.Stat(mdPath); err != nil {
			continue
		}
		dirs = append(dirs, e.Name())
		data, err := os.ReadFile(mdPath)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
			t.Fatalf("%s: SKILL.md 含 UTF-8 BOM", e.Name())
		}
		if bytes.Contains(data, []byte{'\r'}) {
			t.Fatalf("%s: SKILL.md 必须是 LF，不能有 CR", e.Name())
		}
		lines := strings.Split(string(data), "\n")
		if len(lines) < 3 || lines[0] != "---" {
			t.Fatalf("%s: frontmatter 必须以 --- 开始", e.Name())
		}
		end := -1
		for i := 1; i < len(lines); i++ {
			if lines[i] == "---" {
				end = i
				break
			}
		}
		if end < 0 {
			t.Fatalf("%s: frontmatter 未闭合", e.Name())
		}
		fields := map[string]string{}
		for _, ln := range lines[1:end] {
			if strings.TrimSpace(ln) == "" {
				t.Fatalf("%s: frontmatter 不能有空行（闭合会被推迟到正文里的 ---）", e.Name())
			}
			key, val, ok := strings.Cut(ln, ":")
			if !ok {
				t.Fatalf("%s: frontmatter 含非键值行 %q", e.Name(), ln)
			}
			key = strings.TrimSpace(key)
			if !knownKeys[key] {
				t.Fatalf("%s: 未知 frontmatter 键 %q", e.Name(), key)
			}
			if _, dup := fields[key]; dup {
				t.Fatalf("%s: frontmatter 键重复 %q", e.Name(), key)
			}
			fields[key] = strings.Trim(strings.TrimSpace(val), `"'`)
		}
		if fields["name"] != e.Name() {
			t.Fatalf("%s: name = %q，必须等于目录名", e.Name(), fields["name"])
		}
		if fields["description"] == "" {
			t.Fatalf("%s: description 为空", e.Name())
		}
		for _, key := range []string{"mcps", "mcp"} {
			for _, name := range splitFrontmatterList(fields[key]) {
				if !mcpNames[name] {
					t.Fatalf("%s: mcps 引用了不存在的 MCP %q（内置名称: %s）", e.Name(), name, strings.Join(sortedKeys(mcpNames), ", "))
				}
			}
		}
	}
	if len(dirs) == 0 {
		t.Fatal("skills/ 下没有 SKILL.md")
	}
	reg, err := skill.LoadDir(skillsDir)
	if err != nil {
		t.Fatalf("LoadDir 整体失败，agent 将失去全部技能: %v", err)
	}
	if len(reg.List()) != len(dirs) {
		t.Fatalf("LoadDir 得到 %d 个技能，目录有 %d 个", len(reg.List()), len(dirs))
	}
	for _, name := range dirs {
		sk, ok := reg.Get(name)
		if !ok || sk.Description == "" {
			t.Fatalf("LoadDir 没有解析出 %s 的 name/description: ok=%v desc=%q", name, ok, sk.Description)
		}
		if name == "scopesentry" {
			if strings.Join(sk.MCPs, ",") != "ScopeSentry" {
				t.Fatalf("scopesentry mcps = %v，DB 里的 MCP 名是 ScopeSentry", sk.MCPs)
			}
		}
	}
}

func splitFrontmatterList(v string) []string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "[")
	v = strings.TrimSuffix(v, "]")
	if v == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.Trim(strings.TrimSpace(p), `"'`)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// 测试失败信息只求稳定，不引入 sort 以外的逻辑。
	for i := 1; i < len(out); i++ {
		j := i
		for j > 0 && out[j] < out[j-1] {
			out[j], out[j-1] = out[j-1], out[j]
			j--
		}
	}
	return out
}

func repoRoot(t *testing.T) string {
	t.Helper()
	for _, c := range []string{".", ".."} {
		st, err := os.Stat(filepath.Join(c, "skills"))
		if err == nil && st.IsDir() {
			abs, err := filepath.Abs(c)
			if err != nil {
				t.Fatal(err)
			}
			return abs
		}
	}
	t.Fatal("找不到 skills/")
	return ""
}

func seededMCPNames(t *testing.T, root string) map[string]bool {
	t.Helper()
	re := regexp.MustCompile(`(?s)INSERT INTO mcp_servers\b.{0,400}?VALUES\s*\(\s*'([^']+)'`)
	names := map[string]bool{}
	for _, rel := range []string{filepath.Join("db", "schema.sql"), filepath.Join("db", "db.go")} {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllSubmatch(b, -1) {
			names[string(m[1])] = true
		}
	}
	if !names["ScopeSentry"] || !names["browser"] {
		t.Fatalf("内置 MCP 种子不完整: %v", names)
	}
	return names
}
