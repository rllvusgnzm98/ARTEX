package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/tools"
	actool "github.com/Autumn-27/norma/tool"
)

func TestToolAvailabilityDataPATHAndAdvertising(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fixture")
	}
	pg := openTestPG(t)
	data := t.TempDir()
	bin := filepath.Join(data, "tools")
	if err := os.MkdirAll(bin, 0755); err != nil {
		t.Fatal(err)
	}
	writeStubCommand(t, bin, "ffuf")
	if err := os.WriteFile(filepath.Join(bin, "httpx"), []byte("#!/bin/sh\necho 'Python HTTPX'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	oldResolve := agent.ToolResolve
	oldBinding := agent.FindingTrafficBindingEnabled
	t.Cleanup(func() { agent.ToolResolve = oldResolve; agent.FindingTrafficBindingEnabled = oldBinding })
	wireTools(pg, nil, data)
	for _, key := range []string{"ffuf", "httpx"} {
		row, err := pg.GetTool(key)
		if err != nil || row == nil {
			t.Fatalf("get tool %s: %v", key, err)
		}
		t.Cleanup(func() {
			agents, _ := json.Marshal(row.Agents)
			if err := pg.UpdateTool(row.Key, row.Description, row.Schema, agents, row.Enabled); err != nil {
				t.Errorf("restore tool: %v", err)
			}
		})
		if _, err := pg.Exec(`UPDATE tools SET enabled=true, agents='["worker"]'::jsonb WHERE key=$1`, key); err != nil {
			t.Fatal(err)
		}
	}
	desc := names(agent.ToolResolve(t.Context(), "worker", actool.DefaultTools()))["Bash"].Description()
	if !strings.Contains(desc, "- ffuf:") || strings.Contains(desc, "- httpx:") {
		t.Fatalf("managed PATH/identity not reflected in Bash: %s", desc)
	}
	if _, err := os.Stat(filepath.Join(bin, "ffuf")); err != nil {
		t.Fatal(err)
	}
	if !shellHintOnPATH(t.Context(), "ffuf", data) {
		t.Fatal("data/tools command not found")
	}
	if err := os.Remove(filepath.Join(bin, "ffuf")); err != nil {
		t.Fatal(err)
	}
	if shellHintOnPATH(t.Context(), "ffuf", data) {
		t.Fatal("removed command still advertised")
	}
}

func TestToolAvailabilityAPIRequiresAuthentication(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fixture")
	}
	_, ring, key := newTestRing(t)
	data := t.TempDir()
	if err := os.MkdirAll(filepath.Join(data, "tools"), 0755); err != nil {
		t.Fatal(err)
	}
	writeStubCommand(t, filepath.Join(data, "tools"), "ffuf")
	t.Setenv("PATH", t.TempDir())
	s := &Server{m: &Manager{dir: data}, jwtKey: key, jwtRing: ring}
	h := s.Handler()
	token, err := signJWT(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, auth := range []bool{false, true} {
		req := httptest.NewRequest(http.MethodGet, "/api/system/tools", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		if auth {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if !auth {
			if rec.Code != 401 {
				t.Fatalf("unauthenticated: %d %s", rec.Code, rec.Body)
			}
			continue
		}
		var report []tools.Availability
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &report) != nil || len(report) != len(agent.ShellHintSeeds()) {
			t.Fatalf("availability API: %d %s", rec.Code, rec.Body)
		}
		expectedOptional := map[string]bool{
			"nxc":                true,
			"evil-winrm":         true,
			"impacket-ntlmrelayx": true,
			"certipy":            true,
			"bloodhound-python":  true,
			"msfconsole":         true,
		}
		for _, r := range report {
			if r.Name == "ffuf" && (!r.Available || r.Path != filepath.Join(data, "tools", "ffuf")) {
				t.Fatalf("wrong report: %+v", r)
			}
			if r.Optional != expectedOptional[r.Name] {
				t.Fatalf("wrong optional policy: %+v", r)
			}
		}
	}
}
