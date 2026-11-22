package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

func TestBashCommandReadOnly(t *testing.T) {
	for _, command := range []string{
		"cat foo.txt", "ls -la /tmp", "grep -r needle .", "rg pat", "dig example.com",
		"whois example.com", "find . -name '*.go'", "head -n 5 f", "wc -l f", "stat f",
		`grep "a b" f`, `grep 'a|b;$(literal)' f`, `echo "a;b & c | (d) {e} <f>"`,
		`cat *.txt`, `ls ~/?[ab]*`, `cat a\ b`, `echo \$literal`, `echo "\$literal"`,
		`echo '\'`, `"ls" -la`, `r\g pat`, `printf '%s' 'a b'`, "\t cat f \t", "true", "false",
	} {
		t.Run(command, func(t *testing.T) {
			if !bashCommandReadOnly(command) {
				t.Errorf("inspection command serialized: %q", command)
			}
		})
	}
	for _, command := range []string{
		"rm -rf x", "echo hi > out", "cat a && rm b", "cat a; ls", "cat a | tee b",
		"curl http://x", "nmap x", "foo=1 ls", "cat $(whoami)", "cat `whoami`",
		"find . -delete", "find . -exec rm {} ;", "sort -o out f", "tail -f log", "sed -i s/a/b/ f",
		"/bin/ls", "./s.sh", "", " \t ", "cat < f", "cat f &", "cat f\nls", "cat f\n",
		"echo (x)", "echo {x,y}", "echo $HOME", "cat \"$(whoami)\"", "echo \"`whoami`\"",
		`cat 'unterminated`, `cat "unterminated`, "cat f\\", "cat f\\\n", "cat f\x00",
		"find . -execdir ls", "find . -ok ls", "find . -okdir ls", "find . -fprint out",
		"find . -fprintf out fmt", "find . -fprint0 out", "find . -fls out", "find . '-delete'",
		"sort --output=out f", "sort -oout f", "tail -F log", "tail -nf log", "tail --follow=name log",
		"tail --fol log", "head -f f", "rg --pre rm f", "rg --pre=rm f", "rg --hostname-bin rm",
		"rg * f", "find . -del*", "find . *", `"r\g" pat`, "env rm f", "hostname changed",
		"date -s now", "xxd -r input output", "file -C", "ss -K", "lsof -D cache", "sleep 1",
		"tee out", "dd if=f of=g", "awk x", "ip addr", "yes", "top",
	} {
		t.Run(command, func(t *testing.T) {
			if bashCommandReadOnly(command) {
				t.Errorf("unsafe command marked concurrent: %q", command)
			}
		})
	}
}

func TestConcurrentBashWrapper(t *testing.T) {
	inner := actool.NewBash()
	wrapped := wrapConcurrentBash(inner)
	for _, tc := range []struct {
		input string
		safe  bool
	}{
		{`{"command":"cat f"}`, true}, {`{"command":"rm -rf x"}`, false},
		{`{`, false}, {`{}`, false}, {`null`, false}, {`[]`, false}, {`{"command":42}`, false},
		// A background launch registers a task; it must stay serial so a
		// same-turn TaskList can't race ahead of job registration.
		{`{"command":"cat f","run_in_background":true}`, false},
		{`{"command":"cat f","run_in_background":false}`, true},
	} {
		in := json.RawMessage(tc.input)
		if wrapped.IsConcurrencySafe(in) != tc.safe {
			t.Errorf("wrong concurrency decision: %s", in)
		}
		if wrapped.IsReadOnly(in) != inner.IsReadOnly(in) {
			t.Errorf("read-only policy changed: %s", in)
		}
		pc := permission.Context{}
		if !reflect.DeepEqual(wrapped.CheckPermissions(t.Context(), in, pc), inner.CheckPermissions(t.Context(), in, pc)) {
			t.Errorf("permissions changed: %s", in)
		}
	}
	if wrapped.Name() != "Bash" || wrapped.Description() != inner.Description() || wrapped.Prompt() != inner.Prompt() || !reflect.DeepEqual(wrapped.InputSchema(), inner.InputSchema()) {
		t.Fatal("tool metadata changed")
	}
	in := json.RawMessage(`{"command":"printf wrapper-delegated"}`)
	tc := &actool.ToolContext{WorkingDir: t.TempDir()}
	got, err := wrapped.Call(t.Context(), in, tc)
	want, wantErr := inner.Call(t.Context(), in, tc)
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(err, wantErr) {
		t.Fatalf("Call not delegated: %+v %v / %+v %v", got, err, want, wantErr)
	}
	other := actool.NewRead()
	if wrapConcurrentBash(other) != other {
		t.Fatal("non-Bash tool was wrapped")
	}
	var found bool
	for _, tool := range defaultToolsExcept("Glob") {
		if tool.Name() == "Glob" {
			t.Fatal("excluded tool returned")
		}
		if tool.Name() == "Bash" {
			found = true
			if !tool.IsConcurrencySafe(json.RawMessage(`{"command":"cat f"}`)) {
				t.Fatal("default Bash was not wrapped")
			}
		}
	}
	if !found {
		t.Fatal("default Bash missing")
	}
}

type bashScheduleProvider struct {
	commands []string
	requests int
	results  []string
}

func (p *bashScheduleProvider) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.requests++
	if p.requests == 1 {
		var blocks []llm.ContentBlock
		for i, command := range p.commands {
			input, _ := json.Marshal(map[string]string{"command": command})
			blocks = append(blocks, llm.ContentBlock{Type: llm.BlockToolUse, ID: fmt.Sprint(i), Name: "Bash", Input: input})
		}
		return llm.Message{Role: llm.RoleAssistant, Content: blocks}, "tool_use", llm.Usage{}, nil
	}
	for _, msg := range req.Messages {
		for _, b := range msg.Content {
			if b.Type == llm.BlockToolResult {
				p.results = append(p.results, b.ToolUseID+":"+actool.Result{Content: b.Content}.Flatten())
			}
		}
	}
	return assistantText("done"), "end_turn", llm.Usage{}, nil
}

func (p *bashScheduleProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		message, stop, _, err := p.Complete(ctx, req)
		if err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		for _, b := range message.Content {
			if b.Type == llm.BlockToolUse {
				if !yield(llm.StreamEvent{Type: llm.SEToolUseStart, ToolID: b.ID, ToolName: b.Name}, nil) {
					return
				}
				if !yield(llm.StreamEvent{Type: llm.SEToolInputJSON, Text: string(b.Input)}, nil) {
					return
				}
			} else if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: b.Text}, nil) {
				return
			}
		}
		if !yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: stop}, nil) {
			return
		}
		yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}

func TestBashConcurrencySchedulerContract(t *testing.T) {
	for _, nonStreaming := range []bool{false, true} {
		for _, tc := range []struct {
			name     string
			commands []string
			peak     int32
		}{
			{"safe", []string{"cat first", "cat second"}, 2},
			{"serial", []string{"rm first", "rm second"}, 1},
			{"exclusive", []string{"cat first", "rm second", "cat third"}, 1},
		} {
			t.Run(fmt.Sprintf("%s/nonStreaming=%v", tc.name, nonStreaming), func(t *testing.T) {
				var active, peak atomic.Int32
				finished := make(chan string, len(tc.commands))
				stub := actool.Build(actool.Spec{
					Name: "Bash", Schema: map[string]any{"type": "object", "properties": map[string]any{"command": map[string]any{"type": "string"}}},
					Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
						return permission.Allowed()
					},
					Run: func(ctx context.Context, _ json.RawMessage, call *actool.ToolContext) (actool.Result, error) {
						n := active.Add(1)
						defer active.Add(-1)
						for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
						}
						delay := 200 * time.Millisecond
						if call.ToolUseID == "0" {
							delay = 260 * time.Millisecond
						}
						timer := time.NewTimer(delay)
						defer timer.Stop()
						select {
						case <-timer.C:
						case <-ctx.Done():
							return actool.Result{}, ctx.Err()
						}
						finished <- call.ToolUseID
						return actool.Text(call.ToolUseID), nil
					},
				})
				provider := &bashScheduleProvider{commands: tc.commands}
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				start := time.Now()
				text, err := agentcore.Run(ctx, agentcore.Options{Provider: provider, Tools: []actool.CoreTool{wrapConcurrentBash(stub)}, PermissionMode: permission.ModeBypass, MaxTurns: 3, WorkingDir: t.TempDir(), NonStreaming: nonStreaming}, "run the fixtures")
				elapsed := time.Since(start)
				if err != nil || text != "done" {
					t.Fatalf("session failed: %q %v", text, err)
				}
				if peak.Load() != tc.peak {
					t.Fatalf("peak=%d want=%d", peak.Load(), tc.peak)
				}
				var want []string
				for i := range tc.commands {
					want = append(want, fmt.Sprintf("%d:%d", i, i))
				}
				if !reflect.DeepEqual(provider.results, want) {
					t.Fatalf("results reordered: %v want=%v", provider.results, want)
				}
				if tc.peak == 2 {
					if elapsed >= 520*time.Millisecond {
						t.Fatalf("concurrent calls took %v (>= 2x longest call)", elapsed)
					}
					if first := <-finished; first != "1" {
						t.Fatalf("fixture did not finish out of order: %s", first)
					}
				}
				t.Logf("peak=%d elapsed=%v FIFO=%v", peak.Load(), elapsed, provider.results)
			})
		}
	}
}
