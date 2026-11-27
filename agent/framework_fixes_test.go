package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

func TestEnsureTaskSharedDirAndPrompts(t *testing.T) {
	t.Cleanup(func() { PromptOverride = nil })
	PromptOverride = nil

	root := t.TempDir()
	taskDir := ensureRunDir(root, 253, 0)
	shared := ensureTaskSharedDir(taskDir)
	if shared != filepath.Join(taskDir, "shared") {
		t.Fatalf("shared dir = %s", shared)
	}
	st, err := os.Stat(shared)
	if err != nil || !st.IsDir() {
		t.Fatalf("shared dir missing: %v", err)
	}
	runDir := ensureRunDir(root, 253, 14216)
	if got := sharedDirForRun(runDir); got != shared {
		t.Fatalf("worker shared dir = %s, want %s", got, shared)
	}
	workerSpec := workerArtifactSpec(runDir)
	if !strings.Contains(workerSpec, runDir) || !strings.Contains(workerSpec, shared) || !strings.Contains(workerSpec, "artifact_paths") {
		t.Fatalf("worker artifact spec missing shared contract:\n%s", workerSpec)
	}
	planner := plannerSystem("取得域控 C 盘 flag", root, taskDir)
	if !strings.Contains(planner, shared) || !strings.Contains(planner, "artifact_paths") {
		t.Fatalf("planner prompt missing shared dir:\n%s", planner)
	}
}

func TestGoalsPromptForbidsBindingEntryToUnprovenRole(t *testing.T) {
	t.Cleanup(func() { PromptOverride = nil })
	PromptOverride = nil
	got := goalsPrompt("/data", true)
	for _, want := range []string{
		"入口地址不是内部角色",
		"入口与角色分开写",
		"192.168.111.20",
		"取得域控机器 C 盘根目录下的 flag",
		"add_task_scope",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("goals prompt missing %q", want)
		}
	}
}

func TestWorkerSettlementPromptDeclaresBashUnloaded(t *testing.T) {
	t.Cleanup(func() { WrapupOverride = nil })
	WrapupOverride = nil
	perRun := wrapupSettlement("worker", []string{"Bash"})
	if !strings.HasPrefix(perRun.Prompt, "当前为纯写库结算轮，Bash 已卸载") {
		t.Fatalf("per-run settlement prompt = %q", perRun.Prompt)
	}
	clamped := wrapupSettlementForTask("worker", []string{"Bash"}, true)
	if !strings.Contains(clamped.Prompt, "Bash 已卸载") {
		t.Fatalf("clamped fallback prompt = %q", clamped.Prompt)
	}
	timeoutPrompt := clamped.PromptByReason[harness.ReasonTimeout]
	if !strings.Contains(timeoutPrompt, "Bash 已卸载") || !strings.Contains(timeoutPrompt, "整个任务已到达超时上限") {
		t.Fatalf("task-timeout settlement prompt = %q", timeoutPrompt)
	}
	WrapupOverride = func(agentKey string) (string, bool) {
		if agentKey == "worker" {
			return "只写库，别再探测。", true
		}
		return "", false
	}
	custom := wrapupSettlement("worker", []string{"Bash"})
	if !strings.HasPrefix(custom.Prompt, settlementBashUnloadedNotice) || !strings.Contains(custom.Prompt, "只写库，别再探测。") {
		t.Fatalf("db override lost the bash-unloaded notice: %q", custom.Prompt)
	}
}

func TestWorkerExecuteStaticSystemPromptAndNoOutOfScopeAutoExpand(t *testing.T) {
	t.Cleanup(func() { PromptOverride = nil })
	PromptOverride = nil

	d, es := retentionStore(t)
	var taskID int64
	if err := d.QueryRow(`SELECT id FROM tasks WHERE exploration_id=$1`, es.ID()).Scan(&taskID); err != nil {
		t.Fatal(err)
	}
	as := d.Assets()
	if _, err := as.AddAgentScope(taskID, "cidr", "192.168.111.0/24", "initial seed target", "seed"); err != nil {
		t.Fatal(err)
	}
	inScopeID, err := as.UpsertIP(db.UpsertIPReq{IP: "192.168.111.20", TaskID: taskID})
	if err != nil {
		t.Fatal(err)
	}
	outScopeID, err := as.UpsertSubdomain(db.UpsertSubdomainReq{Domain: "drifted.external.invalid", TaskID: taskID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM assets WHERE id IN ($1,$2)`, inScopeID, outScopeID) })

	iid1, err := es.AddIntent(map[string]any{
		"summary":   "枚举 192.168.111.20 Web 服务",
		"asset_ids": []int64{inScopeID},
	}, 5, []int64{inScopeID}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	iid2, err := es.AddIntent(map[string]any{
		"summary":   "核验 drifted.external.invalid 外部引用",
		"asset_ids": []int64{outScopeID},
	}, 5, []int64{outScopeID}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	intent1, _ := es.GetNode(iid1)
	intent2, _ := es.GetNode(iid2)

	var captured []llm.CompletionRequest
	fake := budgetFakeProvider{complete: func(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		captured = append(captured, req)
		return assistantText("done"), "end_turn", llm.Usage{}, nil
	}}
	w := NewWorker(fake, "fake", t.TempDir(), nil, 128000, 3)
	w.SetNonStreaming(func() bool { return true })
	w.SetCredentialSeed(func(context.Context, int64) string {
		return "\n\n<untrusted-data source=\"inherited-credentials\">[{\"username\":\"svc\"}]</untrusted-data>"
	})

	if _, _, err := w.Execute(t.Context(), "w1", taskID, as, es, intent1, nil, nil, nil, nil); err != nil {
		t.Fatalf("execute intent1: %v", err)
	}
	if _, _, err := w.Execute(t.Context(), "w2", taskID, as, es, intent2, nil, nil, nil, nil); err != nil {
		t.Fatalf("execute intent2: %v", err)
	}
	if len(captured) != 2 {
		t.Fatalf("captured %d requests, want 2", len(captured))
	}
	sys1 := strings.Join(captured[0].System, "\n---\n")
	sys2 := strings.Join(captured[1].System, "\n---\n")
	if sys1 != sys2 {
		t.Fatalf("SystemPrompt must remain byte-for-byte static across intents in the same task!\nlen1=%d len2=%d", len(sys1), len(sys2))
	}
	for _, dynamicMarker := range []string{"【你领到的意图", "target-assets", "【进场预塞", "inherited-credentials"} {
		if strings.Contains(sys1, dynamicMarker) {
			t.Fatalf("per-intent dynamic block %q leaked into static SystemPrompt", dynamicMarker)
		}
	}
	var userParts []string
	for _, m := range captured[0].Messages {
		if m.Role == llm.RoleUser {
			userParts = append(userParts, m.Text())
		}
	}
	firstUser1 := strings.Join(userParts, "\n")
	for _, want := range []string{"【你领到的意图", "target-assets", "192.168.111.20", "【进场预塞", "inherited-credentials"} {
		if !strings.Contains(firstUser1, want) {
			t.Fatalf("first user message missing moved dynamic block %q:\n%s", want, firstUser1)
		}
	}
	// Out-of-scope asset must NOT be auto-added into task_scope when trusted seed scope exists.
	rows, err := as.ListTaskScope(taskID)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Domain == "drifted.external.invalid" {
			t.Fatalf("worker auto-expanded task_scope for out-of-scope asset: %+v", r)
		}
	}
	_ = json.Marshal
}
