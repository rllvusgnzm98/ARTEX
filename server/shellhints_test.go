package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

func openTestPG(t *testing.T) *db.DB {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { pg.Close() })
	return pg
}

func writeStubCommand(t *testing.T, dir, name string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		// Windows 的 LookPath 只认 PATHEXT 里的扩展名，无后缀脚本永远找不到。
		path := filepath.Join(dir, name+".cmd")
		if err := os.WriteFile(path, []byte("@echo off\nexit /b 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestWireShellHintCatalogAndBashPATH(t *testing.T) {
	pg := openTestPG(t)
	t.Setenv("AGENT_CORE_DISABLE_INTERACTIVE_SHELL", "1")

	// Fresh catalog rows for this test: drop the seeded keys then seed again
	// via wireTools (same path as startup). User-owned rows are left alone.
	for _, s := range agent.ShellHintSeeds() {
		if _, err := pg.Exec(`DELETE FROM tools WHERE key=$1 AND system=true`, s.Key); err != nil {
			t.Fatal(err)
		}
	}
	userKey := "t-shellhint-user-keep"
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM tools WHERE key=$1`, userKey) })
	_, _ = pg.Exec(`DELETE FROM tools WHERE key=$1`, userKey)
	if err := pg.CreateCustomTool(&db.Tool{
		Key: userKey, Description: "user shell", Kind: "shell",
		Agents: []string{"worker"}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	wireTools(pg, nil)
	t.Cleanup(func() { agent.ToolResolve = nil })

	for _, s := range agent.ShellHintSeeds() {
		row, err := pg.GetTool(s.Key)
		if err != nil || row == nil {
			t.Fatalf("startup did not insert %s: %v", s.Key, err)
		}
		if row.Kind != "shell" || row.Deferred || !row.System {
			t.Fatalf("%s kind=%s deferred=%v system=%v", s.Key, row.Kind, row.Deferred, row.System)
		}
		if !contains(row.Agents, "worker") || !contains(row.Agents, "pentest") {
			t.Fatalf("%s agents=%v", s.Key, row.Agents)
		}
	}
	user, err := pg.GetTool(userKey)
	if err != nil || user == nil || user.Description != "user shell" || user.System {
		t.Fatalf("user row not preserved: %+v %v", user, err)
	}

	// Existing DB: user-edited catalog row and a same-key non-shell row must not
	// be overwritten on a second startup seed.
	nmap, err := pg.GetTool("nmap")
	if err != nil || nmap == nil {
		t.Fatal(err)
	}
	if err := pg.UpdateTool("nmap", "user nmap desc", nmap.Schema, mustJSON([]string{"worker"}), true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM tools WHERE key='nmap'`)
		_ = pg.SeedShellHint("nmap", nmap.Description, mustJSON(nmap.Agents))
	})

	foreignKey := "t-shellhint-foreign-kind"
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM tools WHERE key=$1`, foreignKey) })
	_, _ = pg.Exec(`DELETE FROM tools WHERE key=$1`, foreignKey)
	if _, err := pg.Exec(`
INSERT INTO tools(key, system, description, schema, agents, enabled, kind, deferred)
VALUES ($1, true, 'already builtin', '{}'::jsonb, '["planner"]'::jsonb, true, 'builtin', false)`, foreignKey); err != nil {
		t.Fatal(err)
	}
	// Second seed (startup again).
	seedShellHints(pg)
	edited, err := pg.GetTool("nmap")
	if err != nil || edited == nil || edited.Description != "user nmap desc" {
		t.Fatalf("edited nmap overwritten: %+v %v", edited, err)
	}
	if edited.Kind != "shell" {
		t.Fatalf("edited nmap kind=%s", edited.Kind)
	}
	if contains(edited.Agents, "pentest") {
		t.Fatalf("edited nmap binding overwritten: %v", edited.Agents)
	}
	foreign, err := pg.GetTool(foreignKey)
	if err != nil || foreign == nil || foreign.Kind != "builtin" || foreign.Description != "already builtin" {
		t.Fatalf("non-shell row mutated: %+v %v", foreign, err)
	}

	ts := agent.NewToolSet(nil, "")
	base := append(ts.WorkerTools(), actool.DefaultTools()...)
	ctx := context.Background()

	// LookPath is evaluated at resolve time, not cached at seed/startup.
	empty := t.TempDir()
	t.Setenv("PATH", empty)
	if desc := names(agent.ToolResolve(ctx, "worker", base))["Bash"].Description(); strings.Contains(desc, "- ffuf:") || strings.Contains(desc, "- nmap:") {
		t.Fatalf("empty PATH must not advertise catalog CLIs: %s", desc)
	}

	stub := t.TempDir()
	writeStubCommand(t, stub, "ffuf")
	writeStubCommand(t, stub, "nmap")
	// Alias only: must not advertise impacket-secretsdump.
	writeStubCommand(t, stub, "secretsdump.py")
	t.Setenv("PATH", stub)
	resolved := agent.ToolResolve(ctx, "worker", base)
	byName := names(resolved)

	for _, s := range agent.ShellHintSeeds() {
		if _, ok := byName[s.Key]; ok {
			t.Errorf("shell hint %s must not be a callable tool", s.Key)
		}
	}
	bash, ok := byName["Bash"]
	if !ok {
		t.Fatal("worker lost Bash")
	}
	desc := bash.Description()
	if !strings.Contains(desc, "以下工具已安装在此 bash 环境中") {
		t.Fatalf("Bash missing installed-tool preface: %s", desc)
	}
	if !strings.Contains(desc, "- ffuf:") || !strings.Contains(desc, "- nmap:") {
		t.Fatalf("PATH-present exact names missing from Bash desc: %s", desc)
	}
	if strings.Contains(desc, "sqlmap") || strings.Contains(desc, "impacket-secretsdump") || strings.Contains(desc, "secretsdump.py") {
		t.Fatalf("absent or alias names must not be advertised: %s", desc)
	}

	// Unbound (planner) and disabled rows are not advertised.
	planner := names(agent.ToolResolve(ctx, "planner", base))
	pbash, ok := planner["Bash"]
	if !ok {
		t.Fatal("planner lost Bash")
	}
	if strings.Contains(pbash.Description(), "以下工具已安装在此 bash 环境中") && strings.Contains(pbash.Description(), "- nmap:") {
		// nmap is bound only to worker (we stripped pentest and planner is not bound).
		t.Fatalf("planner should not inherit worker-only nmap advertisement: %s", pbash.Description())
	}

	if err := pg.UpdateTool("ffuf", "disabled ffuf", json.RawMessage(`{}`), mustJSON([]string{"worker", "pentest"}), false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ff, _ := agent.ShellHintByKey("ffuf")
		_ = pg.ResetShellHint("ffuf", ff.Desc, mustJSON(agent.ShellHintDefaultAgents()))
	})
	again := names(agent.ToolResolve(ctx, "worker", base))
	if strings.Contains(again["Bash"].Description(), "- ffuf:") {
		t.Fatalf("disabled ffuf still advertised: %s", again["Bash"].Description())
	}

	// Disabled/not-on-PATH rows remain in the table.
	row, err := pg.GetTool("sqlmap")
	if err != nil || row == nil || row.Kind != "shell" {
		t.Fatalf("missing sqlmap row after PATH filter: %+v %v", row, err)
	}

	// Reset restores code default and keeps kind=shell.
	if err := pg.ResetShellHint("nmap", "should-be-replaced-by-mgmt-path", mustJSON([]string{"worker"})); err != nil {
		t.Fatal(err)
	}
	sd, _ := agent.ShellHintByKey("nmap")
	if err := pg.ResetShellHint("nmap", sd.Desc, mustJSON(agent.ShellHintDefaultAgents())); err != nil {
		t.Fatal(err)
	}
	restored, err := pg.GetTool("nmap")
	if err != nil || restored == nil {
		t.Fatal(err)
	}
	if restored.Kind != "shell" || restored.Description != sd.Desc || restored.Deferred {
		t.Fatalf("reset nmap: kind=%s desc=%q deferred=%v", restored.Kind, restored.Description, restored.Deferred)
	}
	if !contains(restored.Agents, "worker") || !contains(restored.Agents, "pentest") {
		t.Fatalf("reset nmap agents=%v", restored.Agents)
	}

	// UpsertToolForce (the builtin reset path) must not recast nmap as builtin.
	err = pg.UpsertToolForce("nmap", "builtin smash", json.RawMessage(`{}`), mustJSON([]string{"planner"}))
	if err == nil {
		t.Fatal("UpsertToolForce should refuse a shell row")
	}
	still, err := pg.GetTool("nmap")
	if err != nil || still == nil || still.Kind != "shell" || still.Description == "builtin smash" {
		t.Fatalf("UpsertToolForce recast or rewrote nmap: %+v %v", still, err)
	}
}

func TestShellHintsStayOutOfDeferredBlock(t *testing.T) {
	pg := openTestPG(t)
	wireTools(pg, nil)
	t.Cleanup(func() { agent.ToolResolve = nil })

	for _, s := range agent.ShellHintSeeds() {
		row, err := pg.GetTool(s.Key)
		if err != nil || row == nil {
			t.Fatalf("%s missing: %v", s.Key, err)
		}
		if row.Deferred {
			t.Errorf("%s unexpectedly deferred", s.Key)
		}
	}

	// customTools / hostTools deferred list is built from system=false rows;
	// catalog seeds are system=true and must not appear even if we also insert
	// a deferred custom shell row (kind=shell is skipped).
	customKey := "t-shellhint-deferred-custom"
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM tools WHERE key=$1`, customKey) })
	_, _ = pg.Exec(`DELETE FROM tools WHERE key=$1`, customKey)
	if err := pg.CreateCustomTool(&db.Tool{
		Key: customKey, Description: "custom shell", Kind: "shell",
		Agents: []string{"worker"}, Enabled: true, Deferred: true,
	}); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: &Manager{pg: pg}}
	tools, deferred := s.hostTools()
	for _, tool := range tools {
		for _, s := range agent.ShellHintSeeds() {
			if tool.Name() == s.Key {
				t.Errorf("catalog shell hint %s appeared as a callable host tool", s.Key)
			}
		}
		if tool.Name() == customKey {
			t.Errorf("custom shell hint %s appeared as a callable host tool", customKey)
		}
	}
	for _, s := range agent.ShellHintSeeds() {
		if _, ok := deferred[s.Key]; ok {
			t.Errorf("catalog shell hint %s entered deferred binds", s.Key)
		}
	}
	if _, ok := deferred[customKey]; ok {
		t.Errorf("kind=shell custom tool entered deferred binds")
	}
}

func TestPgResetToolShellHintKeepsKind(t *testing.T) {
	pg := openTestPG(t)
	wireTools(pg, nil)
	t.Cleanup(func() { agent.ToolResolve = nil })

	sd, ok := agent.ShellHintByKey("jq")
	if !ok {
		t.Fatal("jq missing from catalog")
	}
	t.Cleanup(func() {
		_ = pg.ResetShellHint(sd.Key, sd.Desc, mustJSON(agent.ShellHintDefaultAgents()))
	})
	if err := pg.UpdateTool("jq", "edited jq", json.RawMessage(`{}`), mustJSON([]string{"worker"}), true); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: &Manager{pg: pg}}
	req := httptest.NewRequest(http.MethodPost, "/api/tools/jq/reset", nil)
	req.SetPathValue("key", "jq")
	rec := httptest.NewRecorder()
	s.pgResetTool(rec, req)
	if rec.Code != 200 {
		t.Fatalf("reset jq status=%d body=%s", rec.Code, rec.Body.String())
	}
	row, err := pg.GetTool("jq")
	if err != nil || row == nil {
		t.Fatal(err)
	}
	if row.Kind != "shell" || row.Description != sd.Desc || row.Deferred {
		t.Fatalf("reset jq: kind=%s desc=%q deferred=%v", row.Kind, row.Description, row.Deferred)
	}
	if !contains(row.Agents, "worker") || !contains(row.Agents, "pentest") {
		t.Fatalf("reset jq agents=%v", row.Agents)
	}
}
