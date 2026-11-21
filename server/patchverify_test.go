package server

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/agent/patchverify"
)

func TestPatchVerifyFixture(t *testing.T) {
	pg := openTestPG(t)
	task, err := pg.CreateTask("patch evidence fixture", "compare harmless banner builds", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(task.ID) })
	store := pg.Exploration(task.ExplorationID)
	taskID := strconv.FormatInt(task.ID, 10)
	manager := &Manager{dir: t.TempDir(), tasks: map[string]*Task{taskID: {ID: taskID, Store: store}}}
	server := &Server{m: manager}
	path, err := server.taskWorkspaceRoot(taskID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}

	run := func(program string, args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), program, args...)
		cmd.Env = append(os.Environ(), "GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
		b, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v: %s", filepath.Base(program), err, b)
		}
		return b
	}
	hash := func(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
	exe := func(name string) string { return filepath.Join(path, name) }
	const source = "../agent/patchverify/testdata/banner/main.go"
	build := func(file, banner string) string {
		t.Helper()
		run("go", "build", "-ldflags=-X main.banner="+banner, "-o", exe(file), source)
		b, err := os.ReadFile(exe(file))
		if err != nil {
			t.Fatal(err)
		}
		return hash(b)
	}
	before, after := "before.exe", "after.exe"
	beforeHash, afterHash := build(before, "classic"), build(after, "modern")
	goVersion := strings.TrimSpace(string(run("go", "version")))
	for _, file := range []string{before, after} {
		if out := string(run("go", "version", exe(file))); !strings.Contains(out, "go1.") {
			t.Fatalf("go version did not recognize the compiled sample: %q", out)
		}
	}

	pair := func(input, beforeOutput, afterOutput, beforeOutcome, afterOutcome string) patchverify.Pair {
		t.Helper()
		observe := func(file, want, outcome string) patchverify.Observation {
			b := run(exe(file), input)
			if strings.TrimSpace(string(b)) != want {
				t.Fatalf("%s output: got %q, want %q", file, b, want)
			}
			return patchverify.Observation{InputID: "fixture-" + input, InputSHA256: hash([]byte(input)),
				EvidenceRef: file + "-observation-" + input, Outcome: outcome, ResultSHA256: hash(b)}
		}
		return patchverify.Pair{Vulnerable: observe(before, beforeOutput, beforeOutcome), Fixed: observe(after, afterOutput, afterOutcome)}
	}
	pins := func(version, digest, backport string) patchverify.Pins {
		return patchverify.Pins{Vendor: "ARTEX fixture", Product: "banner", Version: version, Build: "fixture-" + version,
			Architecture: runtime.GOARCH, SampleSHA256: digest, BackportState: backport}
	}
	a := patchVerifyInput{
		Spec: patchverify.Spec{
			Vulnerable: pins("1", beforeHash, "unknown"), Fixed: pins("2", afterHash, "upstream-fixed"),
			Preflight: patchverify.Preflight{Tool: "go", Version: goVersion, Dependencies: []string{"Go standard library (" + goVersion + ")"},
				Platform: runtime.GOOS + "/" + runtime.GOARCH, SampleSHA256: beforeHash, EvidenceRef: "go-version-on-fixtures", Passed: true},
			RootCause: patchverify.RootCause{Advisory: "FIXTURE-banner-update", File: "main.go", Function: "main"},
			Reachability: patchverify.Reachability{
				Input:  patchverify.Check{Reached: true, EvidenceRef: "fixture-command"},
				Call:   patchverify.Check{Reached: true, EvidenceRef: "fixture-output"},
				Config: patchverify.Check{Reached: true, EvidenceRef: "fixture-linker-banner-setting"},
			},
			SafeToReproduce: true, SafeReason: "owned offline fixture only changes display text",
		},
		VulnerableFile: before, FixedFile: after, Severity: "low",
		Regression: patchverify.Regression{
			Differential:    pair("banner", "classic", "modern", "effect", "no_effect"),
			Normal:          pair("normal", "normal", "normal", "normal", "normal"),
			Denied:          pair("unsupported", "denied", "denied", "denied", "denied"),
			EnvironmentDiff: "same host and Go version; only linker banner setting differed",
			IsolationRef:    "temp task workspace; local standard-library-only CLI fixture",
		},
	}
	explicitID, err := store.AddIntent(map[string]any{"summary": "fixture comparison", "chain_tags": []string{"patch"}}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	keywordID, err := store.AddIntent(map[string]any{"summary": "patch diff fixture"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	tool := server.patchVerifyTools()[0]
	for _, tc := range []struct {
		name string
		edit func(*patchVerifyInput)
		want patchverify.Verdict
	}{
		{"verified", func(*patchVerifyInput) {}, patchverify.Verified},
		{"candidate", func(a *patchVerifyInput) { a.Reachability.Call.Reached = false }, patchverify.Candidate},
		{"blocked", func(a *patchVerifyInput) { a.Preflight.SampleSHA256 = afterHash }, patchverify.Blocked},
		{"unverified", func(a *patchVerifyInput) { a.SafeToReproduce = false }, patchverify.Unverified},
		{"hash mismatch", func(a *patchVerifyInput) { a.VulnerableFile = after }, patchverify.Blocked},
		{"workspace escape", func(a *patchVerifyInput) { a.VulnerableFile = filepath.Join("..", before) }, patchverify.Blocked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := a
			tc.edit(&args)
			in, err := json.Marshal(args)
			if err != nil {
				t.Fatal(err)
			}
			ctx := agent.WithRunInfo(t.Context(), agent.RunInfo{TaskID: task.ID, IntentID: explicitID, ExplorationID: task.ExplorationID})
			result, err := tool.Call(ctx, in, nil)
			if err != nil {
				t.Fatal(err)
			}
			out := toolResultJSON(t, result)
			if out["verdict"] != string(tc.want) {
				t.Fatalf("verdict = %v, want %s: %v", out["verdict"], tc.want, out["reason"])
			}
			_, recommended := out["recommended_finding"]
			if recommended != (tc.want == patchverify.Verified) {
				t.Fatal("unexpected recommendation status")
			}
			if tc.want == patchverify.Verified {
				report := out["report"].(string)
				for _, value := range []string{goVersion, beforeHash, afterHash, a.Preflight.Platform, a.Preflight.Dependencies[0], a.Regression.EnvironmentDiff} {
					if !strings.Contains(report, value) {
						t.Errorf("report missing %q", value)
					}
				}
				finding := out["recommended_finding"].(map[string]any)
				if finding["intent_id"] != float64(explicitID) || finding["evidence"] != report {
					t.Fatal("finding handoff must link intent and report")
				}
			}
			if tc.want == patchverify.Unverified && !strings.Contains(out["report"].(string), "cannot be safely reproduced, not verified, no PoC provided") {
				t.Fatal("report missing safety limitation")
			}
		})
	}
	runInfo := agent.RunInfo{TaskID: task.ID, IntentID: keywordID, ExplorationID: task.ExplorationID}
	result, err := tool.Call(agent.WithRunInfo(t.Context(), runInfo), json.RawMessage("{}"), nil)
	if err != nil || !result.IsError || !strings.Contains(result.Flatten(), "chain_tags") {
		t.Fatalf("keyword-only intent not rejected: %q (%v)", result.Flatten(), err)
	}
	runInfo.IntentID = explicitID
	result, err = tool.Call(agent.WithRunInfo(t.Context(), runInfo), json.RawMessage(`{"payload":"ignored"}`), nil)
	if err != nil || !result.IsError {
		t.Fatal("tool accepted an input payload")
	}
}

func TestExplicitPatchTag(t *testing.T) {
	for _, tc := range []struct{ payload, want string }{
		{`{"summary":"patch diff"}`, ""},
		{`{"chain_tags":["web"],"summary":"patch diff"}`, ""},
		{`{"chain_tags":["web"," Rev "]}`, "rev"},
		{`{"chain_tags":["firmware","patch"]}`, "firmware"},
		{`{"chain_tags":"patch"}`, ""},
	} {
		if got := explicitPatchTag(json.RawMessage(tc.payload)); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.payload, got, tc.want)
		}
	}
}
