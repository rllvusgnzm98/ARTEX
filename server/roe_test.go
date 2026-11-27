package server

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
)

// RoE 测试改全局 roe_enforcement，并可能替换 loadTaskScopeRows。
// 不调用 t.Parallel，避免与同包其它用例交错。

func withRoEMode(t *testing.T, pg *db.DB, mode string) {
	t.Helper()
	prev, ok, err := pg.GetSetting(settingRoEEnforcement)
	if err != nil {
		t.Fatalf("read roe_enforcement: %v", err)
	}
	if err := pg.SetSetting(settingRoEEnforcement, mode); err != nil {
		t.Fatalf("set roe_enforcement: %v", err)
	}
	t.Cleanup(func() {
		var cerr error
		if ok {
			cerr = pg.SetSetting(settingRoEEnforcement, prev)
		} else {
			_, cerr = pg.Exec(`DELETE FROM settings WHERE key=$1`, settingRoEEnforcement)
		}
		if cerr != nil {
			t.Errorf("restore roe_enforcement: %v", cerr)
		}
	})
}

func swapScopeLoader(t *testing.T, fn func(*db.DB, int64) ([]db.TaskScope, error)) {
	t.Helper()
	orig := loadTaskScopeRows
	loadTaskScopeRows = fn
	t.Cleanup(func() { loadTaskScopeRows = orig })
}

func roeFixture(t *testing.T, mode string) (*db.DB, *db.Task, *Server) {
	t.Helper()
	pg := openTestPG(t)
	withRoEMode(t, pg, mode)
	task, err := pg.CreateTask("roe b2 "+mode, "scope check", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(task.ID) })
	if _, err := pg.Assets().AddAgentScope(task.ID, "cidr", "10.255.255.0/24", "roe fixture", "manual"); err != nil {
		t.Fatalf("AddAgentScope: %v", err)
	}
	s := &Server{m: &Manager{pg: pg, assets: pg.Assets()}}
	return pg, task, s
}

func TestRoEStrictReadFailureDenies(t *testing.T) {
	_, task, s := roeFixture(t, "strict")
	const leak = "postgres://roe-user:roe-secret@10.1.2.3:5432/artex"
	swapScopeLoader(t, func(*db.DB, int64) ([]db.TaskScope, error) {
		return nil, fmt.Errorf("dial %s: connection refused", leak)
	})
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: task.ID})
	msg, err := s.roeCheckHost(ctx, "10.255.0.9", "立足点目标")
	if err == nil || msg != "" {
		t.Fatalf("strict 读失败应拒绝: msg=%q err=%v", msg, err)
	}
	got := err.Error()
	for _, want := range []string{"范围读取失败", "strict 拒绝", "warn/off 回退"} {
		if !strings.Contains(got, want) {
			t.Errorf("错误缺少 %q: %s", want, got)
		}
	}
	if strings.Contains(got, leak) || strings.Contains(got, "roe-secret") || strings.Contains(got, "postgres://") {
		t.Fatalf("错误泄露了读取失败细节: %s", got)
	}
}

func TestRoEWarnReadFailureAllowsWithMark(t *testing.T) {
	pg, task, s := roeFixture(t, "warn")
	const leak = "postgres://roe-user:roe-secret@10.1.2.3:5432/artex"
	swapScopeLoader(t, func(*db.DB, int64) ([]db.TaskScope, error) {
		return nil, fmt.Errorf("dial %s: connection refused", leak)
	})
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: task.ID})
	msg, err := s.roeCheckHost(ctx, "10.255.0.9", "立足点目标")
	if err != nil {
		t.Fatalf("warn 读失败应放行: %v", err)
	}
	const want = "⚠ RoE 授权范围检查：范围读取失败，warn 下放行（非未登记范围）。"
	if msg != want {
		t.Fatalf("warn = %q, want %q", msg, want)
	}
	if strings.Contains(msg, leak) || strings.Contains(msg, "postgres://") {
		t.Fatalf("告警泄露了读取失败细节: %s", msg)
	}

	// 未登记范围是直接放行、没有 ⚠。读失败的告警必须和它区分开。
	bareTask, berr := pg.CreateTask("roe b2 no scope", "empty scope", nil, 0, 0)
	if berr != nil {
		t.Fatalf("CreateTask: %v", berr)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(bareTask.ID) })
	loadTaskScopeRows = func(pg *db.DB, taskID int64) ([]db.TaskScope, error) {
		if pg == nil {
			return nil, fmt.Errorf("范围存储未就绪")
		}
		return pg.Assets().ListTaskScope(taskID)
	}
	bareCtx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: bareTask.ID})
	bare, berr := s.roeCheckHost(bareCtx, "10.255.0.9", "立足点目标")
	if berr != nil || bare != "" {
		t.Fatalf("未登记范围应静默放行: msg=%q err=%v", bare, berr)
	}
	if bare == msg {
		t.Fatal("读失败告警不得与未登记范围相同")
	}
}

func TestRoEOffAllowsWithoutScopeRead(t *testing.T) {
	_, task, s := roeFixture(t, "off")
	calls := 0
	swapScopeLoader(t, func(*db.DB, int64) ([]db.TaskScope, error) {
		calls++
		return nil, fmt.Errorf("off 不应读范围")
	})
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: task.ID})
	msg, err := s.roeCheckHost(ctx, "10.255.0.9", "立足点目标")
	if err != nil || msg != "" {
		t.Fatalf("off 应放行: msg=%q err=%v", msg, err)
	}
	if calls != 0 {
		t.Fatalf("off 读了 %d 次范围", calls)
	}
	verdict, mode, verr := s.roeVerdictFor(task.ID, "10.255.0.9")
	if verr != nil || mode != "off" || verdict != guard.ScopeUnknown {
		t.Fatalf("off verdict = %v %q %v", verdict, mode, verr)
	}
	if calls != 0 {
		t.Fatalf("roeVerdictFor(off) 读了范围")
	}
}

func TestRoEStrictOutOfScopeDeniesAndInScopeAllows(t *testing.T) {
	_, task, s := roeFixture(t, "strict")
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: task.ID})
	msg, err := s.roeCheckHost(ctx, "10.255.0.9", "立足点目标")
	if err == nil || msg != "" {
		t.Fatalf("strict 越界应拒绝: msg=%q err=%v", msg, err)
	}
	want := fmt.Sprintf("RoE 授权范围检查：立足点目标 10.255.0.9 不在本任务(task %d)已登记范围内。如需放行：把目标加入任务范围(add_task_scope)，或在系统设置把 roe_enforcement 改为 warn/off。", task.ID)
	if err.Error() != want {
		t.Fatalf("越界文案 = %q\nwant %q", err.Error(), want)
	}
	if msg, err = s.roeCheckHost(ctx, "10.255.255.9", "立足点目标"); err != nil || msg != "" {
		t.Fatalf("范围内应放行: msg=%q err=%v", msg, err)
	}

	withRoEMode(t, s.m.pg, "warn")
	msg, err = s.roeCheckHost(ctx, "10.255.0.9", "立足点目标")
	if err != nil || msg != "⚠ "+want {
		t.Fatalf("warn 越界应带 ⚠ 放行: msg=%q err=%v", msg, err)
	}

	withRoEMode(t, s.m.pg, "nope")
	msg, err = s.roeCheckHost(ctx, "10.255.0.9", "立足点目标")
	if err != nil || msg != "⚠ "+want {
		t.Fatalf("未知模式应按 warn 放行: msg=%q err=%v", msg, err)
	}
}

func TestRoENonTaskRunAllows(t *testing.T) {
	_, task, s := roeFixture(t, "strict")
	calls := 0
	swapScopeLoader(t, func(*db.DB, int64) ([]db.TaskScope, error) {
		calls++
		return nil, fmt.Errorf("非任务运行不应读范围")
	})
	msg, err := s.roeCheckHost(context.Background(), "10.255.0.9", "立足点目标")
	if err != nil || msg != "" || calls != 0 {
		t.Fatalf("TaskID<=0 应放行且不读范围: msg=%q err=%v calls=%d", msg, err, calls)
	}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: task.ID})
	msg, err = s.roeCheckHost(ctx, "  ", "立足点目标")
	if err != nil || msg != "" || calls != 0 {
		t.Fatalf("空 host 应放行: msg=%q err=%v calls=%d", msg, err, calls)
	}
	s.m.pg = nil
	msg, err = s.roeCheckHost(ctx, "10.255.0.9", "立足点目标")
	if err != nil || msg != "" || calls != 0 {
		t.Fatalf("存储未就绪应放行: msg=%q err=%v calls=%d", msg, err, calls)
	}
}

func TestRoEStrictIgnoresAutoAndAgentScopeExpansionAndHonorsExclusions(t *testing.T) {
	pg := openTestPG(t)
	withRoEMode(t, pg, "strict")
	task, err := pg.CreateTask("roe strict h1", "bounty isolation", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(task.ID) })
	as := pg.Assets()
	if _, err := as.AddAgentScope(task.ID, "root_domain", "acme.test", "H1 program scope", "manual"); err != nil {
		t.Fatalf("manual root_domain: %v", err)
	}
	if _, err := as.AddAgentScope(task.ID, "exclude_subdomain", "blog.acme.test", "H1 out-of-scope", "manual"); err != nil {
		t.Fatalf("manual exclude_subdomain: %v", err)
	}
	// Simulate worker insert_assets auto-scope and agent add_task_scope attempting to widen into evil.other.test.
	if err := as.AddAutoScope(task.ID, "subdomain", "evil.other.test", "", ""); err != nil {
		t.Fatalf("AddAutoScope: %v", err)
	}
	if _, err := as.AddAgentScope(task.ID, "subdomain", "agent-added.other.test", "discovered in JS", "agent"); err != nil {
		t.Fatalf("agent AddAgentScope: %v", err)
	}

	s := &Server{m: &Manager{pg: pg, assets: as}}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: task.ID})
	cfg := newRoEConfig(pg)
	rules, err := cfg.Scope(task.ID)
	if err != nil {
		t.Fatalf("cfg.Scope: %v", err)
	}
	matcher := guard.NewScopeMatcher(rules)
	if got := matcher.Check("api.acme.test"); got != guard.ScopeIn {
		t.Fatalf("manual root_domain child should be ScopeIn, got %v", got)
	}
	if got := matcher.Check("blog.acme.test"); got != guard.ScopeOut {
		t.Fatalf("excluded subdomain should be ScopeOut, got %v", got)
	}
	if got := matcher.Check("evil.other.test"); got != guard.ScopeOut {
		t.Fatalf("auto-scoped domain must stay ScopeOut in strict mode, got %v", got)
	}
	if got := matcher.Check("agent-added.other.test"); got != guard.ScopeOut {
		t.Fatalf("agent-scoped domain must stay ScopeOut in strict mode, got %v", got)
	}

	// Verify roeCheckHost and proxyRoEDeps agree.
	if msg, err := s.roeCheckHost(ctx, "api.acme.test", "target"); err != nil || msg != "" {
		t.Fatalf("api.acme.test should pass: msg=%q err=%v", msg, err)
	}
	for _, blockedHost := range []string{"blog.acme.test", "evil.other.test", "agent-added.other.test"} {
		if _, err := s.roeCheckHost(ctx, blockedHost, "target"); err == nil {
			t.Errorf("%s should be blocked in strict mode", blockedHost)
		}
	}
	tp := &taskProxyManager{}
	tp.useRoE(s.m.proxyRoEDeps())
	gate := tp.hostGate(task.ID)
	if err := gate("api.acme.test"); err != nil {
		t.Errorf("proxy gate should allow api.acme.test: %v", err)
	}
	if err := gate("evil.other.test"); err == nil {
		t.Errorf("proxy gate should block auto-scoped evil.other.test in strict mode")
	}

	// Manual approval of subdomain grants exact access (while still rejecting its children).
	if _, err := as.AddAgentScope(task.ID, "subdomain", "evil.other.test", "operator approved", "manual"); err != nil {
		t.Fatalf("manual approve subdomain: %v", err)
	}
	s.m.InvalidateProxyRoE(task.ID)
	tp.invalidateRoE(task.ID)
	if _, err := s.roeCheckHost(ctx, "evil.other.test", "target"); err != nil {
		t.Fatalf("manually approved subdomain should pass: %v", err)
	}
	if _, err := s.roeCheckHost(ctx, "deep.evil.other.test", "target"); err == nil {
		t.Fatalf("manual subdomain must match exact host, not child deep.evil.other.test")
	}
}

func TestRoEStrictSeedScopeEnforcesAndCallbackExempts(t *testing.T) {
	pg := openTestPG(t)
	withRoEMode(t, pg, "strict")
	t.Setenv("ARTEX_CALLBACK_ADDR", "198.51.100.77:4444")

	task, err := pg.CreateTask("roe strict seed", "round-0 seed target", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(task.ID) })

	as := pg.Assets()
	if _, err := as.AddAgentScope(task.ID, "ip", "192.168.111.20", "goal seed", "seed"); err != nil {
		t.Fatalf("seed scope: %v", err)
	}
	// Runtime agent scope addition must NOT widen strict boundary.
	if _, err := as.AddAgentScope(task.ID, "ip", "10.255.0.9", "runtime guess", "agent"); err != nil {
		t.Fatalf("agent scope: %v", err)
	}

	s := &Server{m: &Manager{pg: pg, assets: as}}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: task.ID})

	if msg, err := s.roeCheckHost(ctx, "192.168.111.20", "target"); err != nil || msg != "" {
		t.Fatalf("seed target should pass in strict mode: msg=%q err=%v", msg, err)
	}
	if _, err := s.roeCheckHost(ctx, "10.255.0.9", "target"); err == nil {
		t.Fatal("strict mode with seed scope must block out-of-scope / runtime-agent target (no ScopeUnknown fail-open)")
	}
	if msg, err := s.roeCheckHost(ctx, "198.51.100.77", "target"); err != nil || msg != "" {
		t.Fatalf("ARTEX_CALLBACK_ADDR host should be auto-exempted: msg=%q err=%v", msg, err)
	}
}
