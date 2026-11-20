package agent

import (
	"strings"
	"testing"
	"unicode/utf8"

	actool "github.com/Autumn-27/norma/tool"
)

func TestPlannerRenderTodos(t *testing.T) {
	for _, empty := range [][]actool.Todo{nil, {}} {
		if got := renderPlannerTodos(empty); got != "" {
			t.Errorf("renderPlannerTodos(%#v) = %q, want empty", empty, got)
		}
	}

	items := []actool.Todo{
		{Status: actool.TodoCompleted, Content: "已核对资料"},
		{Status: actool.TodoPending, Content: "整理记录"},
		{Status: "unknown", Content: "待确认状态"},
		{Status: actool.TodoInProgress, Content: "编写摘要"},
	}
	got := renderPlannerTodos(items)
	const rows = "\n  ✔ 已核对资料\n  ☐ 整理记录\n  ☐ 待确认状态\n  ▶ 编写摘要\n"
	before, after, ok := strings.Cut(got, rows)
	if !ok || !strings.Contains(before, "你的规划待办") {
		t.Fatalf("renderPlannerTodos() lost the heading or ordered rows: %q", got)
	}
	if !strings.HasPrefix(after, "据此推进") || !strings.Contains(after, "TodoWrite") {
		t.Errorf("renderPlannerTodos() missing closing instruction after todo rows: %q", after)
	}
}

func TestPlannerRenderTruncOutput(t *testing.T) {
	const suffix = " …（已截断，完整见 get_worker_output）"
	for _, tt := range []struct {
		name, input, want string
		limit             int
	}{
		{name: "below limit", input: "中文", want: "中文", limit: 3},
		{name: "exact rune limit", input: "中🙂文", want: "中🙂文", limit: 3},
		{name: "truncate after multibyte rune", input: "中🙂文A", want: "中🙂" + suffix, limit: 2},
		{name: "zero limit", input: "中", want: suffix, limit: 0},
		{name: "empty at zero limit", limit: 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := truncOutput(tt.input, tt.limit)
			if got != tt.want || !utf8.ValidString(got) {
				t.Errorf("truncOutput(%q, %d) = %q, want valid UTF-8 %q", tt.input, tt.limit, got, tt.want)
			}
		})
	}
}

func TestPlannerRenderGraphOverview(t *testing.T) {
	for _, tt := range []struct {
		name string
		data map[string]any
		json string
	}{
		{
			name: "snapshot",
			data: map[string]any{"facts": 2, "task": map[string]any{"title": "示例"}},
			json: `{"facts":2,"task":{"title":"示例"}}`,
		},
		{name: "nil snapshot", json: "null"},
		{name: "unserializable snapshot", data: map[string]any{"value": make(chan int)}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := renderGraphOverview(tt.data)
			if tt.json == "" {
				if got != "" {
					t.Errorf("renderGraphOverview() = %q, want empty on marshal error", got)
				}
				return
			}
			heading, json, ok := strings.Cut(strings.TrimPrefix(got, "\n\n"), "\n")
			if !ok || !strings.Contains(heading, "本轮态势") || !strings.Contains(heading, "graph_overview") || json != tt.json {
				t.Errorf("renderGraphOverview() = %q, want overview heading followed by %s", got, tt.json)
			}
		})
	}
}
