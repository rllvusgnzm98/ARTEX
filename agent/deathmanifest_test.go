package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

// shellBackgrounded 只认引号外结尾的裸 &；&&、|&、引号内的 & 都不是后台化。
func TestShellBackgrounded(t *testing.T) {
	cases := map[string]bool{
		"nohup nc -l 4444 &":              true,
		"python3 -m http.server 8080 &  ": true,
		"echo a && echo b":                false,
		"echo a && echo b &":              true,  // 结尾的 & 在 shell 语义里把整个命令列表后台化
		"curl a & curl b":                 false, // & 在中间
		"echo 'x&' ":                      false, // 结尾无 &
		"echo 'unclosed &":                false, // 引号未闭合，放弃判定
		"echo \"end &\"":                  false, // & 在引号内
		`echo foo \&`:                     false, // 反斜杠转义的 & 不是后台化
		`echo foo \\&`:                    true,  // 双反斜杠转义了反斜杠自身，结尾 & 生效
		"printf '%s' foo |& tee x":        false,
		"nc -l 4444":                      false,
		"":                                false,
	}
	for cmd, want := range cases {
		if got := shellBackgrounded(cmd); got != want {
			t.Fatalf("shellBackgrounded(%q)=%v want %v", cmd, got, want)
		}
	}
}

// 记账：结果文本里的出生公告（含 task id 与输出路径）必须入台账；
// 显式 run_in_background 与 shell 内 & 也要记；普通前台命令不记。
func TestDeathLedgerRecording(t *testing.T) {
	l := &deathLedger{}
	tool := &deathLedgerTool{ledger: l}

	// 前台超时自动转后台的公告。
	tool.record(json.RawMessage(`{"command":"nc -l 4444 -k"}`),
		actool.Text("Command still running after 2m0s; moved to background as task-7. Output file: /tmp/norma/s1/tasks/task-7.out\nUse TaskOutput"))
	if len(l.snapshot()) != 1 {
		t.Fatalf("background announcement must be recorded, got %d", len(l.snapshot()))
	}
	r := l.snapshot()[0]
	if r.TaskID != "task-7" || r.OutputPath != "/tmp/norma/s1/tasks/task-7.out" || r.Kind != "managed" {
		t.Fatalf("bad record: %+v", r)
	}

	// run_in_background=true 的即时公告（Running in background as ...）。
	tool.record(json.RawMessage(`{"command":"sleep 300","run_in_background":true}`),
		actool.Text("Running in background as task-8. Output file: /tmp/norma/s1/tasks/task-8.out"))
	if len(l.snapshot()) != 2 {
		t.Fatalf("explicit background must be recorded")
	}

	// shell 内 & 起跳（无任何公告文本）。
	tool.record(json.RawMessage(`{"command":"nohup python3 -m http.server 80 &"}`), actool.Text(""))
	last := l.snapshot()[len(l.snapshot())-1]
	if last.Kind != "shell-bg" {
		t.Fatalf("shell & must record as shell-bg, got %+v", last)
	}

	// 普通前台命令不记账。
	before := len(l.snapshot())
	tool.record(json.RawMessage(`{"command":"curl http://t/"}`), actool.Text("200 OK"))
	if len(l.snapshot()) != before {
		t.Fatal("foreground command must not be recorded")
	}
}

// 收尾写出：台账非空时必须双份落盘（runDir + shared/），输出尾段拷进 shared
// 且清单里记绝对路径；台账为空不落任何文件。
func TestWriteDeathManifest(t *testing.T) {
	root := t.TempDir()
	runDir := filepath.Join(root, "tasks", "5", "i12")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// 空台账：不落盘。
	empty := &deathLedger{}
	writeDeathManifest(runDir, 12, empty)
	if _, err := os.Stat(filepath.Join(runDir, "death_manifest_i12.json")); !os.IsNotExist(err) {
		t.Fatal("empty ledger must not produce a manifest")
	}

	// 造一个模拟的后台输出文件（比上限长，验证只拷尾段）。
	srcOut := filepath.Join(root, "task-7.out")
	big := strings.Repeat("x", deathManifestMaxOutputBytes) + "TAIL-MARKER"
	if err := os.WriteFile(srcOut, []byte(big), 0o644); err != nil {
		t.Fatal(err)
	}

	l := &deathLedger{}
	l.add(bgRecord{Command: "nc -l 4444 -k", TaskID: "task-7", OutputPath: srcOut, Kind: "managed", SpawnedAt: time.Now()})
	l.add(bgRecord{Command: "nohup python3 -m http.server 80 &", Kind: "shell-bg", SpawnedAt: time.Now()})
	writeDeathManifest(runDir, 12, l)

	for _, dir := range []string{runDir, filepath.Join(root, "tasks", "5", "shared")} {
		data, err := os.ReadFile(filepath.Join(dir, "death_manifest_i12.json"))
		if err != nil {
			t.Fatalf("manifest missing in %s: %v", dir, err)
		}
		var m deathManifest
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatalf("manifest in %s not valid json: %v", dir, err)
		}
		if len(m.Entries) != 2 {
			t.Fatalf("manifest must have 2 entries, got %d", len(m.Entries))
		}
		if !strings.Contains(m.Note, "删除本清单") {
			t.Fatalf("manifest note must instruct lifecycle deletion, got %q", m.Note)
		}
		// 第一条有输出尾段：文件存在于 shared/，内容为尾段、含 TAIL-MARKER、不超长。
		tail := m.Entries[0].TailFile
		if !filepath.IsAbs(tail) {
			t.Fatalf("tail_file must be an absolute path, got %q", tail)
		}
		content, err := os.ReadFile(tail)
		if err != nil {
			t.Fatalf("tail file unreadable: %v", err)
		}
		if !strings.HasSuffix(string(content), "TAIL-MARKER") {
			t.Fatal("tail copy must keep the end of the output")
		}
		if int64(len(content)) > deathManifestMaxOutputBytes {
			t.Fatalf("tail copy exceeds %d bytes", deathManifestMaxOutputBytes)
		}
		// shell-bg 条目无 tail。
		if m.Entries[1].TailFile != "" {
			t.Fatalf("shell-bg entry must not have a tail file: %+v", m.Entries[1])
		}
	}
}

// 进场注入：shared/ 里的清单渲染成接管段；陈旧（>24h）与畸形清单被剔除；
// 无任何现场时返回空串。
func TestDeathManifestBlock(t *testing.T) {
	root := t.TempDir()
	runDir := filepath.Join(root, "tasks", "5", "i20")
	shared := filepath.Join(root, "tasks", "5", "shared")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatal(err)
	}

	// 无清单：空串。
	if got := deathManifestBlock(runDir, 20); got != "" {
		t.Fatalf("no manifest must render empty, got %q", got)
	}

	// shared/ 里放一份新鲜清单（模拟 i12 撤退现场）。
	m := deathManifest{
		WrittenAt: time.Now(),
		IntentID:  12,
		Note:      "n",
		Entries:   []deathManifestEntry{{Command: "nc -l 4444 -k", Kind: "managed", TaskID: "task-7", SpawnedAt: time.Now()}},
	}
	data, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(shared, "death_manifest_i12.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	// 再放一份陈旧清单（mtime 调成 25h 前）与一份畸形清单——都必须被剔除。
	if err := os.WriteFile(filepath.Join(shared, "death_manifest_i9.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-25 * time.Hour)
	if err := os.Chtimes(filepath.Join(shared, "death_manifest_i9.json"), old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shared, "death_manifest_i8.json"), []byte("not-json"), 0o644); err != nil {
		t.Fatal(err)
	}

	block := deathManifestBlock(runDir, 20)
	if block == "" {
		t.Fatal("fresh shared manifest must render a block")
	}
	if !strings.Contains(block, "nc -l 4444 -k") {
		t.Fatalf("block must carry the dead command, got %q", block)
	}
	if !strings.Contains(block, "删除对应清单文件") {
		t.Fatalf("block must instruct lifecycle deletion, got %q", block)
	}
	if strings.Contains(block, "death_manifest_i9.json") {
		t.Fatal("stale manifest must be excluded")
	}

	// 本 runDir 有自己的清单时优先用它（续跑场景），shared 的不重复渲染。
	own := deathManifest{
		WrittenAt: time.Now(), IntentID: 20, Note: "n",
		Entries: []deathManifestEntry{{Command: "socat TCP-L:8080 fork &", Kind: "shell-bg", SpawnedAt: time.Now()}},
	}
	ownData, _ := json.Marshal(own)
	if err := os.WriteFile(filepath.Join(runDir, "death_manifest_i20.json"), ownData, 0o644); err != nil {
		t.Fatal(err)
	}
	block2 := deathManifestBlock(runDir, 20)
	if !strings.Contains(block2, "socat TCP-L:8080") {
		t.Fatalf("own-runDir manifest must win for resumption, got %q", block2)
	}
	if strings.Contains(block2, "nc -l 4444") {
		t.Fatal("shared manifest must not duplicate-render when own exists")
	}
	// 若 shared/ 同时存在同意图副本，提示里必须列出同步副本路径避免删除后留幽灵副本。
	if err := os.WriteFile(filepath.Join(shared, "death_manifest_i20.json"), ownData, 0o644); err != nil {
		t.Fatal(err)
	}
	block3 := deathManifestBlock(runDir, 20)
	if !strings.Contains(block3, filepath.Join(shared, "death_manifest_i20.json")) {
		t.Fatalf("paired shared manifest path must be surfaced for cleanup, got %q", block3)
	}
}

func TestDeathLedgerHooksTracksMonitorAndRemovesStoppedTask(t *testing.T) {
	l := &deathLedger{}
	h := wrapDeathLedgerHooks(nil, l)

	// SDK 内部追加的 Monitor 工具通过 PostToolUse 进入台账。
	resJSON, _ := json.Marshal("Started monitor mon-1. Output file: /tmp/norma/s1/tasks/mon-1.out")
	h.PostToolUse(t.Context(), "Monitor", []byte(`{"command":"tail -f /tmp/oob.log"}`), resJSON, false)
	if got := l.snapshot(); len(got) != 1 || got[0].TaskID != "mon-1" || got[0].OutputPath != "/tmp/norma/s1/tasks/mon-1.out" {
		t.Fatalf("Monitor must be recorded via PostToolUse, got %+v", got)
	}

	// 同 task_id 重复上报去重。
	h.PostToolUse(t.Context(), "Monitor", []byte(`{"command":"tail -f /tmp/oob.log"}`), resJSON, false)
	if len(l.snapshot()) != 1 {
		t.Fatalf("duplicate task_id must be deduplicated, got %d", len(l.snapshot()))
	}

	// 失败的 shell-bg 命令不得误记账。
	h.PostToolUse(t.Context(), "Bash", []byte(`{"command":"badcmd &"}`), []byte(`"command not found"`), true)
	if len(l.snapshot()) != 1 {
		t.Fatalf("errored Bash call must not record shell-bg, got %+v", l.snapshot())
	}

	// TaskStop 成功停止后台任务后应从台账摘除，正常收队不再落误导清单。
	h.PostToolUse(t.Context(), "TaskStop", []byte(`{"task_id":"mon-1"}`), []byte(`"stopped"`), false)
	if len(l.snapshot()) != 0 {
		t.Fatalf("TaskStop must remove stopped task from ledger, got %+v", l.snapshot())
	}
}

func TestWorkerResumeInjectsDeathManifest(t *testing.T) {
	_, store := retentionStore(t)
	iid, err := store.AddIntent(map[string]any{"summary": "resume death manifest check"}, 0, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := store.GetNode(iid)
	if err != nil {
		t.Fatal(err)
	}
	workDir := t.TempDir()
	tx := transcript.NewStore(t.TempDir())
	// 预先写入一条历史 transcript，触发带历史续跑分支 (len(s.Messages()) > 0)。
	sid := WorkerSessionID(store.ID(), intent.ID)
	if err := tx.Append(tx.MainPath(sid),
		transcript.Record{UUID: "u1", SessionID: sid, Type: "message", Message: &llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.TextBlock("previous run")}}},
		transcript.Record{UUID: "a1", SessionID: sid, Type: "message", Message: &llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("started listener")}}},
	); err != nil {
		t.Fatal(err)
	}
	// 在本意图 runDir 与 shared/ 写入撤退现场清单。
	runDir := ensureRunDir(workDir, 42, intent.ID)
	l := &deathLedger{}
	l.add(bgRecord{Command: "nc -lvnp 4444", TaskID: "task-9", Kind: "managed", SpawnedAt: time.Now()})
	writeDeathManifest(runDir, intent.ID, l)

	var seenPrompt string
	fake := budgetFakeProvider{complete: func(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		if len(req.Messages) > 0 {
			seenPrompt = req.Messages[len(req.Messages)-1].Text()
		}
		return assistantText("resumed ok"), "end_turn", llm.Usage{}, nil
	}}
	w := NewWorker(fake, "fake", workDir, tx, 0, 1)
	w.SetNonStreaming(func() bool { return true })
	if _, _, err := w.Execute(t.Context(), "work#1", 42, nil, store, intent, nil, nil, nil, nil); err != nil {
		t.Fatalf("Execute resume failed: %v", err)
	}
	if !strings.Contains(seenPrompt, "【撤退现场清单") || !strings.Contains(seenPrompt, "nc -lvnp 4444") {
		t.Fatalf("resumed worker prompt dropped deathManifestBlock: %q", seenPrompt)
	}
	wantShared := filepath.Join(sharedDirForRun(runDir), fmt.Sprintf("death_manifest_i%d.json", intent.ID))
	if !strings.Contains(seenPrompt, wantShared) {
		t.Fatalf("resumed worker prompt missing paired shared manifest path %q: %q", wantShared, seenPrompt)
	}
}
