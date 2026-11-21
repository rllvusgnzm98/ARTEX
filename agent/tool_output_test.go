package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

func outputProbe(run func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error)) actool.CoreTool {
	return actool.Build(actool.Spec{Name: "mcp__spill__probe", Schema: obj(map[string]any{}), ReadOnly: func(json.RawMessage) bool { return true }, Concurrent: func(json.RawMessage) bool { return true }, Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
		return permission.Allowed()
	}, Run: run})
}

func spillReference(t *testing.T, output string) string {
	t.Helper()
	_, rest, ok := strings.Cut(output, "full output: ")
	if !ok {
		t.Fatalf("missing full-output reference: %q", firstLine(output, 100))
	}
	ref, _, ok := strings.Cut(rest, "]</persisted-output>")
	if !ok {
		t.Fatal("unterminated spill marker")
	}
	return ref
}

func TestToolOutputSpill(t *testing.T) {
	for _, mode := range []string{"under", "at_cap", "over", "blocked", "missing_dir"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			tc := &actool.ToolContext{WorkingDir: dir, OutputDir: cmdOutDir(dir), AgentID: "agent-test", ToolUseID: "call-test", Env: []string{"PROBE=value"}}
			output := strings.Repeat("head\n", 4000) + "MIDDLE_EVIDENCE" + strings.Repeat("tail\n", 4000)
			if mode == "under" {
				output = "unchanged output"
			} else if mode == "at_cap" {
				output = strings.Repeat("x", toolOutputCap)
			} else if mode == "blocked" {
				if err := os.WriteFile(tc.OutputDir, []byte("not a directory"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if mode == "missing_dir" {
				tc.OutputDir = ""
			}
			before := *tc
			logs := &resumeLog{}
			originalLog := log.Writer()
			log.SetOutput(logs)
			t.Cleanup(func() { log.SetOutput(originalLog) })
			probe := outputProbe(func(_ context.Context, _ json.RawMessage, inner *actool.ToolContext) (actool.Result, error) {
				if inner == tc || inner.MaxOutputChars <= len(output) {
					t.Errorf("inner Capture must be disabled on a copied context: %+v", inner)
				}
				copied := *inner
				copied.MaxOutputChars = before.MaxOutputChars
				if !reflect.DeepEqual(copied, before) {
					t.Error("non-cap ToolContext fields changed")
				}
				return actool.Text(actool.Capture(inner, output)), nil
			})
			result, err := (&outputSpillTool{CoreTool: probe}).Call(t.Context(), json.RawMessage(`{}`), tc)
			if err != nil || !reflect.DeepEqual(*tc, before) {
				t.Fatalf("call changed context or returned an error: %v", err)
			}
			got := result.Flatten()
			if mode == "under" || mode == "at_cap" {
				if got != output {
					t.Fatal("under-cap output changed")
				}
				if _, err := os.Stat(tc.OutputDir); !os.IsNotExist(err) {
					t.Fatalf("under-cap output should not create a spill directory: %v", err)
				}
				return
			}
			if len(got) > toolOutputCap+1500 || !strings.HasPrefix(got, output[:toolOutputCap/2]) || !strings.HasSuffix(got, output[len(output)-toolOutputCap/2:]) {
				t.Fatal("output must be bounded head+tail")
			}
			if actool.CaptureOnce(tc, got) != got {
				t.Fatal("SDK post-tool CaptureOnce must not hide the ARTEX marker")
			}
			if mode != "over" {
				want := fmt.Sprintf("middle %d bytes lost — re-run with narrower output]", len(output)-toolOutputCap)
				if !strings.Contains(got, "[output truncated; spill FAILED: ") || !strings.Contains(got, want) || !strings.Contains(logs.String(), "tool=mcp__spill__probe agent=agent-test tool_use=call-test spill FAILED:") {
					t.Fatalf("failure must be explicit to model and logs: %s", got[toolOutputCap/2:len(got)-toolOutputCap/2])
				}
				return
			}
			ref := spillReference(t, got)
			if !strings.HasPrefix(ref, "cmd-output"+string(filepath.Separator)) {
				t.Errorf("spill should be recoverable relative to working dir: %s", ref)
			}
			full, err := os.ReadFile(filepath.Join(dir, ref))
			if err != nil || string(full) != output {
				t.Fatalf("spill lost full content: bytes=%d err=%v", len(full), err)
			}
		})
	}
}

func TestToolOutputPreservesBehavior(t *testing.T) {
	wantErr := errors.New("original error")
	want := actool.Result{IsError: true, Content: []llm.ContentBlock{llm.TextBlock("small"), {Type: llm.BlockThinking}}, Extra: []llm.Message{llm.UserText("extra")}}
	for _, err := range []error{nil, wantErr} {
		inner := actool.Build(actool.Spec{Name: "raw", Description: "description", Prompt: "prompt", Schema: obj(map[string]any{}), RawInput: true,
			ReadOnly: func(json.RawMessage) bool { return true }, Concurrent: func(json.RawMessage) bool { return true },
			Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
				return permission.Denied("unchanged denial")
			},
			Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) { return want, err },
		})
		wrapped := &outputSpillTool{CoreTool: inner}
		got, gotErr := wrapped.Call(t.Context(), nil, nil)
		if gotErr != err || !reflect.DeepEqual(got, want) || wrapped.Name() != inner.Name() || wrapped.Description() != inner.Description() || wrapped.Prompt() != inner.Prompt() || !reflect.DeepEqual(wrapped.InputSchema(), inner.InputSchema()) || !wrapped.AcceptsRawInput() || !wrapped.IsReadOnly(nil) || !wrapped.IsConcurrencySafe(nil) || wrapped.CheckPermissions(t.Context(), nil, permission.Context{}).Behavior != permission.Deny {
			t.Fatalf("tool behavior changed: result=%+v err=%v", got, gotErr)
		}
	}
	wrapped := &outputSpillTool{CoreTool: outputProbe(nil)}
	tc := &actool.ToolContext{MaxOutputChars: 7}
	got := wrapped.capture(tc, strings.Repeat("你好", 20))
	if !utf8.ValidString(got) || !strings.Contains(got, "spill FAILED:") {
		t.Fatal("small byte caps must not split UTF-8 or suppress errors")
	}
}

func TestToolOutputBuiltinRead(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "fixture.txt"), []byte("readable fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	tc := &actool.ToolContext{WorkingDir: dir, OutputDir: cmdOutDir(dir)}
	input := json.RawMessage(`{"file_path":"fixture.txt"}`)
	inner := actool.NewRead()
	want, wantErr := inner.Call(t.Context(), input, tc)
	got, err := (&outputSpillTool{CoreTool: inner}).Call(t.Context(), input, tc)
	if err != wantErr || !reflect.DeepEqual(got, want) || !strings.Contains(got.Flatten(), "readable fixture") {
		t.Fatalf("SDK Read's output-bonus arithmetic must remain valid: %s %v", got.Flatten(), err)
	}
}

type spillProvider struct {
	requests int
	output   string
}

func (p *spillProvider) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.requests++
	if p.requests == 1 {
		return llm.Message{Role: "assistant", Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "spill-call", Name: actool.ExecuteExtraToolName, Input: json.RawMessage(`{"tool_name":"mcp__spill__probe","params":{}}`)}}}, "tool_use", llm.Usage{}, nil
	}
	for _, message := range req.Messages {
		for _, block := range message.Content {
			if block.Type == llm.BlockToolResult {
				for _, content := range block.Content {
					p.output += content.Text
				}
			}
		}
	}
	return assistantText("done"), "end_turn", llm.Usage{}, nil
}

func (*spillProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	panic("test uses non-streaming")
}

func TestToolOutputSessionRunners(t *testing.T) {
	output := strings.Repeat("head\n", 4000) + "FULL_MIDDLE_EVIDENCE" + strings.Repeat("tail\n", 4000)
	oldAugment, oldResolve := ToolAugment, ToolResolve
	t.Cleanup(func() { ToolAugment, ToolResolve = oldAugment, oldResolve })
	ToolResolve = nil
	ToolAugment = func(context.Context, string) ([]actool.CoreTool, DeferredInfo, func()) {
		probe := outputProbe(func(_ context.Context, _ json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			return actool.Text(actool.Capture(tc, output)), nil
		})
		return []actool.CoreTool{probe}, DeferredInfo{Deferred: []string{probe.Name()}, GlobalNames: []string{probe.Name()}, Unlock: actool.NewUnlockSet(probe.Name())}, func() {}
	}
	for _, runner := range []string{"worker", "planner", "mainagent", "chat"} {
		t.Run(runner, func(t *testing.T) {
			d, ts := retentionStore(t)
			var taskID int64
			if err := d.QueryRow(`SELECT id FROM tasks WHERE exploration_id=$1`, ts.ID()).Scan(&taskID); err != nil {
				t.Fatal(err)
			}
			provider := &spillProvider{}
			workDir := t.TempDir()
			var err error
			runDir := ensureRunDir(workDir, taskID, 0)
			switch runner {
			case "worker":
				id, addErr := ts.AddIntent(map[string]any{"summary": "spill probe"}, 0, nil, "planner")
				if addErr != nil {
					t.Fatal(addErr)
				}
				intent, getErr := ts.GetNode(id)
				if getErr != nil {
					t.Fatal(getErr)
				}
				runDir = ensureRunDir(workDir, taskID, id)
				worker := NewWorker(provider, "test", workDir, nil, 128000, 3)
				worker.SetNonStreaming(func() bool { return true })
				_, _, err = worker.ExecuteWithMessage(t.Context(), "spill-worker", taskID, nil, ts, intent, nil, nil, nil, nil, "request", "probe")
			case "planner":
				planner := NewPlanner(provider, "test", workDir, nil, 128000, 3)
				planner.SetNonStreaming(func() bool { return true })
				_, _, err = planner.Plan(t.Context(), taskID, nil, ts, "probe", nil, nil)
			case "mainagent":
				main := NewMainAgent(provider, "test", workDir, nil, 128000, 3)
				main.SetNonStreaming(func() bool { return true })
				_, err = main.Chat(t.Context(), taskID, 0, nil, ts, "probe", "probe", nil, nil, nil, nil, nil)
			case "chat":
				runDir = filepath.Join(workDir, "sessions", "spill-session")
				chat := NewChatAgent(provider, "test", workDir, nil, 128000)
				chat.SetNonStreaming(func() bool { return true })
				_, err = chat.Chat(t.Context(), "test-chat", "spill-session", "probe", 3, time.Minute, false, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			ref := spillReference(t, provider.output)
			full, err := os.ReadFile(filepath.Join(runDir, ref))
			if err != nil || string(full) != output || len(provider.output) > toolOutputCap+1500 {
				t.Fatalf("model must receive bounded output and a readable complete spill: bytes=%d err=%v", len(full), err)
			}
		})
	}
}

func TestAttachToolOutputSpillingIncludesFinalHostTools(t *testing.T) {
	opts := agentcore.Options{}
	AttachStableWebFetch(&opts, "")
	enableNoa(&opts, func() bool { return true }, t.TempDir(), "spill-noa", 128000, func(msg string) { t.Log(msg) })
	attachToolOutputSpilling(&opts)
	for _, tool := range opts.Tools {
		if _, ok := tool.(*outputSpillTool); !ok {
			t.Errorf("host tool %s was not wrapped", tool.Name())
		}
	}
}
