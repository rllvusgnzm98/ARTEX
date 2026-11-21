package tools

import (
	"context"
	"fmt"
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

func TestHTTPXProbeIsolatesHome(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint("failure=", fail), func(t *testing.T) {
			data, home, config, cache, scratch := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("XDG_CONFIG_HOME", config)
			t.Setenv("XDG_CACHE_HOME", cache)
			t.Setenv("TMPDIR", scratch)
			receipt := filepath.Join(data, "probe-home")
			t.Setenv("ARTEX_PROBE_RECEIPT", receipt)
			body := `[ "$#" = 1 ] && [ "$1" = "-version" ] || exit 2
printf '%s' "$HOME" > "$ARTEX_PROBE_RECEIPT"
printf config > "$HOME/httpx-config"
printf config > "$XDG_CONFIG_HOME/xdg-config"
printf cache > "$XDG_CACHE_HOME/xdg-cache"
echo projectdiscovery.io`
			if fail {
				body += "\nexit 1"
			}
			commandFixture(t, data, "httpx", body)
			r := CheckCommand(t.Context(), CommandSpec{Name: "httpx"}, data)
			if r.Available == fail {
				t.Fatalf("unexpected identity result: %+v", r)
			}
			probeHome, err := os.ReadFile(receipt)
			if err != nil {
				t.Fatal(err)
			}
			if filepath.Dir(string(probeHome)) != scratch {
				t.Fatalf("probe not isolated: %q", probeHome)
			}
			if _, err := os.Stat(string(probeHome)); !os.IsNotExist(err) {
				t.Fatalf("probe HOME not cleaned: %v", err)
			}
			for _, dir := range []string{home, config, cache, scratch} {
				entries, err := os.ReadDir(dir)
				if err != nil || len(entries) != 0 {
					t.Fatalf("diagnostic left files in %s: %v %v", dir, entries, err)
				}
			}
		})
	}
}

func TestHTTPXProbeRelativeTMPDIR(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX command fixture")
	}
	caller := t.TempDir()
	t.Chdir(caller)
	if err := os.Mkdir("scratch", 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", "scratch")
	home, config, cache, data := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", config)
	t.Setenv("XDG_CACHE_HOME", cache)
	commandFixture(t, data, "httpx", `[ "$#" = 1 ] && [ "$1" = "-version" ] || exit 2
case "$HOME:$XDG_CONFIG_HOME:$XDG_CACHE_HOME" in /*:/*:/*) ;; *) exit 3 ;; esac
[ "$PWD" = "$HOME" ] || exit 4
printf config > "$HOME/config"
printf config > "$XDG_CONFIG_HOME/xdg-config"
printf cache > "$XDG_CACHE_HOME/xdg-cache"
printf fallback > config.yaml
echo projectdiscovery.io`)
	r := CheckCommand(t.Context(), CommandSpec{Name: "httpx"}, data)
	if !r.Available {
		t.Fatalf("relative TMPDIR probe: %+v", r)
	}
	for _, dir := range []string{home, config, cache, filepath.Join(caller, "scratch")} {
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatalf("diagnostic left files in %s: %v %v", dir, entries, err)
		}
	}
	entries, err := os.ReadDir(caller)
	if err != nil || len(entries) != 1 || entries[0].Name() != "scratch" {
		t.Fatalf("caller cwd changed: %v %v", entries, err)
	}
}

func TestHTTPXProbeTemporaryHomeFailure(t *testing.T) {
	data := t.TempDir()
	commandFixture(t, data, "httpx", "echo projectdiscovery.io")
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	r := CheckCommand(t.Context(), CommandSpec{Name: "httpx"}, data)
	if r.Available || !strings.Contains(r.Error, "create temporary home") {
		t.Fatalf("unexpected result: %+v", r)
	}
}
