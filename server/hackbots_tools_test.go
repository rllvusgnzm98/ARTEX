package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/google/uuid"
)

func TestHackbotsCommandPlaceholders(t *testing.T) {
	const cmd = "{{ARTEX_PYTHON}} {{ARTEX_SKILL_DIR}}/example.py {path} {{ARTEX_DATA_DIR}} {{X}}"
	got, err := expandCommandPlaceholders(cmd, commandPlaceholderValues{
		SkillDir: "/OneDrive - stelpolvo/{path}/skills",
		DataDir:  "/data space",
		Python:   "/opt/$Tools/Python's bin/python",
	}, map[string]any{
		"path": "input file.txt",
		"X":    "leave unknown tokens alone",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `'/opt/$Tools/Python'\''s bin/python' '/OneDrive - stelpolvo/{path}/skills'/example.py 'input file.txt' '/data space' {{X}}`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestHackbotsCommandConditionalBlocks(t *testing.T) {
	const cmd = "run {target}{{IF seed}} --seed {seed}{{END}}{{IF dry_run}} --dry-run{{END}}{{IF host_mode}} --host-mode {host_mode}{{END}}"
	cases := []struct {
		name   string
		params map[string]any
		want   string
	}{
		{"absent", map[string]any{"target": "https://example.com"}, `run 'https://example.com'`},
		{"present", map[string]any{"target": "t", "seed": "https://a/b", "dry_run": true, "host_mode": "exact-host"},
			`run 't' --seed 'https://a/b' --dry-run --host-mode 'exact-host'`},
		{"falsy", map[string]any{"target": "t", "seed": "", "dry_run": false, "host_mode": nil}, `run 't'`},
		{"zero", map[string]any{"target": "t", "seed": float64(0)}, `run 't'`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := expandCommandPlaceholders(cmd, commandPlaceholderValues{
				SkillDir: "/skills", DataDir: "/data", Python: "/usr/bin/python3", Node: "/usr/bin/node",
			}, tc.params)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHackbotsCommandNodePlaceholder(t *testing.T) {
	got, err := expandCommandPlaceholders("{{ARTEX_NODE}} {{ARTEX_SKILL_DIR}}/x.js {dir}", commandPlaceholderValues{
		SkillDir: "/skills", Node: "/usr/local/bin/node",
	}, map[string]any{"dir": "/tmp/out"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `'/usr/local/bin/node' '/skills'/x.js '/tmp/out'`; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestHackbotsCommandPlaceholderErrors(t *testing.T) {
	for _, tt := range []struct {
		token string
		want  string
	}{
		{"{{ARTEX_SKILL_DIR}}", "技能目录未配置"},
		{"{{ARTEX_DATA_DIR}}", "数据目录未配置"},
		{"{{ARTEX_PYTHON}}", "未检测到 python 解释器"},
		{"{{ARTEX_NODE}}", "未检测到 node"},
	} {
		t.Run(tt.token, func(t *testing.T) {
			_, err := expandCommandPlaceholders(tt.token, commandPlaceholderValues{}, nil)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want error containing %q", err, tt.want)
			}
		})
	}
}

// TestHackbotsToolDefinitions 检查清单本身自洽：key 唯一、占位符只用受支持的、
// 绑定只指向内置 agent、脚本路径都落在 skills 目录下。
func TestHackbotsToolDefinitions(t *testing.T) {
	skillRoot := filepath.Join("..", "skills")
	seen := map[string]bool{}
	builtinAgents := map[string]bool{"goals": true, "planner": true, "mainagent": true, "worker": true, "auto": true, "pentest": true}
	for _, tool := range hackbotsTools() {
		if tool.Key == "" || seen[tool.Key] {
			t.Fatalf("duplicate or empty tool key %q", tool.Key)
		}
		seen[tool.Key] = true
		if !json.Valid([]byte(tool.Schema)) {
			t.Errorf("%s: schema is not valid JSON", tool.Key)
		}
		if strings.TrimSpace(tool.Command) == "" {
			t.Errorf("%s: empty command", tool.Key)
		}
		if len(tool.Agents) == 0 {
			t.Errorf("%s: no agent binding", tool.Key)
		}
		for _, a := range tool.Agents {
			if !builtinAgents[a] {
				t.Errorf("%s: unknown agent %q", tool.Key, a)
			}
		}
		for _, token := range commandPlaceholder.FindAllString(tool.Command, -1) {
			switch token {
			case "{{ARTEX_SKILL_DIR}}", "{{ARTEX_DATA_DIR}}", "{{ARTEX_PYTHON}}", "{{ARTEX_NODE}}", "{{END}}":
				continue
			}
			if commandConditionalStart.MatchString(token) {
				continue
			}
			t.Errorf("%s: unsupported placeholder %s", tool.Key, token)
		}
		if !strings.Contains(tool.Command, "{{ARTEX_SKILL_DIR}}") {
			t.Errorf("%s: command does not reference the skills directory", tool.Key)
		}
		if strings.Contains(tool.Command, "codex") || strings.Contains(tool.Command, ".claude") {
			t.Errorf("%s: command references an external agent", tool.Key)
		}
		// 脚本路径必须真实存在，否则播种出一条必然失败的工具。技能包与工具壳
		// 分属两次提交：技能目录整体不在时跳过（半截检出），目录在但脚本缺失
		// 就报错。
		fields := strings.Fields(tool.Command)
		for _, f := range fields {
			if !strings.HasPrefix(f, "{{ARTEX_SKILL_DIR}}/") {
				continue
			}
			rel := strings.TrimPrefix(f, "{{ARTEX_SKILL_DIR}}/")
			skillName := strings.SplitN(rel, "/", 2)[0]
			if _, err := os.Stat(filepath.Join(skillRoot, skillName)); err != nil {
				t.Logf("%s: skill %s not present in this checkout, skip path check", tool.Key, skillName)
				continue
			}
			if _, err := os.Stat(filepath.Join(skillRoot, filepath.FromSlash(rel))); err != nil {
				t.Errorf("%s: script %s not found: %v", tool.Key, rel, err)
			}
		}
	}
	if len(seen) < 9 {
		t.Errorf("expected at least 9 tools, got %d", len(seen))
	}
}

func TestHackbotsCommandMissingDirectory(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	s := &Server{skillDir: missing, m: &Manager{dir: missing}}
	for _, token := range []string{"{{ARTEX_SKILL_DIR}}", "{{ARTEX_DATA_DIR}}"} {
		raw, err := json.Marshal(commandExec{Command: token + "/example"})
		if err != nil {
			t.Fatal(err)
		}
		result, err := s.runCommandTool(context.Background(), raw, nil, nil)
		if err != nil || !result.IsError || !strings.Contains(result.Flatten(), "目录未配置") {
			t.Fatalf("%s: expected directory error, got %v, %v", token, result, err)
		}
	}
}

func TestHackbotsSeedCustomTool(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config: %v", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { pg.Close() })

	key := "test_seed_custom_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	seed := &db.Tool{
		Key: key, Description: "Print a message", Kind: "command", Enabled: true,
		Exec:   json.RawMessage(`{"command":"echo {args}"}`),
		Agents: []string{"worker"},
	}
	if err := pg.SeedCustomTool(seed); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pg.DeleteCustomTool(key); err != nil {
			t.Error(err)
		}
	})

	if err := pg.SeedCustomTool(seed); err != nil {
		t.Fatalf("repeat seed: %v", err)
	}
	rows, err := pg.ListCustomTools()
	if err != nil {
		t.Fatal(err)
	}
	var got *db.Tool
	for _, row := range rows {
		if row.Key == key {
			got = row
			break
		}
	}
	if got == nil || got.System || !got.Enabled || got.Kind != "command" || got.Deferred || string(got.Schema) != "{}" {
		t.Fatalf("unexpected seeded tool: %+v", got)
	}

	restoreBinding := agent.FindingTrafficBindingEnabled
	t.Cleanup(func() {
		agent.ToolResolve = nil
		agent.FindingTrafficBindingEnabled = restoreBinding
	})
	wireTools(pg, nil)
	s := &Server{m: &Manager{pg: pg}}
	tools, err := s.customTools()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if names(agent.ToolResolve(ctx, "worker", tools))[key] == nil {
		t.Fatal("worker lost its bound tool")
	}
	if names(agent.ToolResolve(ctx, "pentest", tools))[key] != nil {
		t.Fatal("pentest received a tool bound only to worker")
	}

	got.Description, got.Enabled, got.Kind = "User edit", false, "script"
	if err := pg.UpdateCustomTool(got); err != nil {
		t.Fatal(err)
	}
	if err := pg.SeedCustomTool(seed); err != nil {
		t.Fatal(err)
	}
	edited, err := pg.GetTool(key)
	if err != nil || edited == nil || edited.Description != "User edit" || edited.Enabled || edited.Kind != "script" {
		t.Fatalf("seed changed user edits: %+v, %v", edited, err)
	}
	if names(agent.ToolResolve(ctx, "worker", tools))[key] != nil {
		t.Fatal("worker received its disabled tool")
	}
}
