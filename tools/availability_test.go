package tools

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func commandFixture(t *testing.T, data, name, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX command fixture")
	}
	dir := filepath.Join(data, "tools")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCommandAvailabilityManagedPATH(t *testing.T) {
	data := t.TempDir()
	t.Setenv("PATH", t.TempDir())
	path := commandFixture(t, data, "fixture-tool", "exit 0")
	r := CheckCommand(t.Context(), CommandSpec{Name: "fixture-tool"}, data)
	if !r.Available || r.Path != path {
		t.Fatalf("data/tools not found: %+v", r)
	}
	parts := filepath.SplitList(CommandPath(data))
	if parts[0] != filepath.Dir(path) || parts[1] != ImageToolsDir {
		t.Fatalf("wrong PATH precedence: %v", parts)
	}
	if strings.Contains(os.Getenv("PATH"), filepath.Dir(path)) {
		t.Fatal("shared PATH must not mutate process environment")
	}
	for _, name := range []string{"", "../bad", "missing-fixture-tool"} {
		if r := CheckCommand(t.Context(), CommandSpec{Name: name, Optional: true}, data); r.Available || r.Error == "" || !r.Optional {
			t.Fatalf("invalid/missing command accepted: %+v", r)
		}
	}
	if got := CheckCommands(t.Context(), nil, data); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestCommandAvailabilityHTTPXIdentity(t *testing.T) {
	data := t.TempDir()
	t.Setenv("PATH", t.TempDir())
	for _, tc := range []struct {
		body string
		ok   bool
	}{
		{"echo 'Python HTTPX 0.28.0'", false},
		{"echo projectdiscovery.io >&2; echo 'Current Version: v1.12.0' >&2", true},
		{"echo projectdiscovery.io; exit 1", false},
	} {
		commandFixture(t, data, "httpx", tc.body)
		r := CheckCommand(t.Context(), CommandSpec{Name: "httpx"}, data)
		if r.Available != tc.ok || r.Path == "" {
			t.Fatalf("httpx identity: %+v", r)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if r := CheckCommand(ctx, CommandSpec{Name: "httpx"}, data); r.Available || r.Error == "" {
		t.Fatalf("cancelled probe: %+v", r)
	}
	var w probeOutput
	w.Write([]byte(strings.Repeat("x", 10000)))
	if len(w.data) != 4096 {
		t.Fatal("probe output is not bounded")
	}
}

func TestAvailabilitySummary(t *testing.T) {
	for _, results := range [][]Availability{nil, {{Name: "one", Available: true}}, {{Name: "optional", Optional: true, Error: "missing"}}, {{Name: "required", Error: "missing"}}} {
		summary, warn := AvailabilitySummary(results)
		if summary == "" || warn != (len(results) > 0 && !results[0].Available) {
			t.Fatalf("summary=%s warning=%v", summary, warn)
		}
	}
}
