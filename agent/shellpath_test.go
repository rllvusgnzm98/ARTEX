package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/tools"
	actool "github.com/Autumn-27/norma/tool"
)

func TestWorkerBashManagedPATH(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX Bash fixture")
	}
	data := t.TempDir()
	bin := filepath.Join(data, "tools")
	if err := os.MkdirAll(bin, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "fixture-tool"), []byte("#!/bin/sh\nprintf managed-path-ok\n"), 0755); err != nil {
		t.Fatal(err)
	}
	var bash actool.CoreTool
	for _, tool := range actool.DefaultTools() {
		if tool.Name() == "Bash" {
			bash = tool
		}
	}
	if bash == nil {
		t.Fatal("Bash missing")
	}
	env := shellEnv(data, []string{"ARTEX_UA=test-agent"})
	if env[len(env)-1] != "PATH="+tools.CommandPath(data) {
		t.Fatal("Bash did not use shared PATH")
	}
	got, err := bash.Call(t.Context(), json.RawMessage(`{"command":"fixture-tool"}`), &actool.ToolContext{WorkingDir: t.TempDir(), Env: env})
	if err != nil || got.IsError || !strings.Contains(got.Flatten(), "managed-path-ok") {
		t.Fatalf("managed tool cannot run: %s %v", got.Flatten(), err)
	}
}
