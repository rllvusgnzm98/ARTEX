package tools

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const ImageToolsDir = "/opt/artex/tools"

func CommandPath(dataDir string) string {
	var dirs []string
	if dataDir != "" {
		dirs = append(dirs, filepath.Join(dataDir, "tools"))
	}
	dirs = append(dirs, ImageToolsDir)
	dirs = append(dirs, filepath.SplitList(os.Getenv("PATH"))...)
	seen := map[string]bool{}
	var out []string
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		abs, err := filepath.Abs(dir)
		if err == nil && !seen[abs] {
			out = append(out, abs)
			seen[abs] = true
		}
	}
	return strings.Join(out, string(os.PathListSeparator))
}

type CommandSpec struct {
	Name     string
	Optional bool
}

type Availability struct {
	Name      string `json:"name"`
	Path      string `json:"path,omitempty"`
	Optional  bool   `json:"optional"`
	Available bool   `json:"available"`
	Identity  string `json:"identity,omitempty"`
	Error     string `json:"error,omitempty"`
}

func CheckCommands(ctx context.Context, specs []CommandSpec, dataDir string) []Availability {
	results := make([]Availability, 0, len(specs))
	for _, spec := range specs {
		results = append(results, CheckCommand(ctx, spec, dataDir))
	}
	return results
}

func CheckCommand(ctx context.Context, spec CommandSpec, dataDir string) Availability {
	r := Availability{Name: spec.Name, Optional: spec.Optional}
	if spec.Name == "" || filepath.Base(spec.Name) != spec.Name {
		r.Error = "invalid command name"
		return r
	}
	for _, dir := range filepath.SplitList(CommandPath(dataDir)) {
		path, err := exec.LookPath(filepath.Join(dir, spec.Name))
		if err == nil {
			r.Path = path
			break
		}
	}
	if r.Path == "" {
		r.Error = "not found on worker PATH"
		return r
	}
	if spec.Name == "httpx" {
		home, err := os.MkdirTemp("", "artex-httpx-probe-")
		if err != nil {
			r.Error = "httpx identity probe: create temporary home: " + err.Error()
			return r
		}
		defer os.RemoveAll(home)
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		out := &probeOutput{}
		cmd := exec.CommandContext(ctx, r.Path, "-version", "-duc")
		cmd.Env = append(os.Environ(), "PATH="+CommandPath(dataDir), "HOME="+home, "XDG_CONFIG_HOME="+home, "XDG_CACHE_HOME="+home)
		cmd.Stdout, cmd.Stderr = out, out
		cmd.WaitDelay = 100 * time.Millisecond
		err = cmd.Run()
		version := strings.ToLower(string(out.data))
		if err != nil || !strings.Contains(version, "projectdiscovery") {
			r.Error = "identity mismatch: httpx must be ProjectDiscovery's CLI (-version)"
			if err != nil {
				r.Error += ": " + err.Error()
			}
			return r
		}
		r.Identity = "ProjectDiscovery httpx"
	}
	r.Available = true
	return r
}

type probeOutput struct{ data []byte }

func (w *probeOutput) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := 4096 - len(w.data); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		w.data = append(w.data, p...)
	}
	return n, nil
}

func AvailabilitySummary(results []Availability) (string, bool) {
	var missing []string
	found := 0
	for _, r := range results {
		if r.Available {
			found++
			continue
		}
		note := r.Name + ": " + r.Error
		if r.Optional {
			note += " (optional)"
		}
		missing = append(missing, note)
	}
	return fmt.Sprintf("available %d/%d; %s", found, len(results), strings.Join(missing, "; ")), len(missing) > 0
}
