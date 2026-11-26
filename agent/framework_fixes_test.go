package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/harness"
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
