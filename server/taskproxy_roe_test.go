package server

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/guard"
)

func TestHostGateStrictBlocks(t *testing.T) {
	const taskID int64 = 7
	const host = "10.255.0.9"
	m := &taskProxyManager{}
	m.useRoE(roeGateDeps{
		mode: func() string { return "strict" },
		scope: func(int64) ([]guard.ScopeRule, error) {
			return []guard.ScopeRule{{Kind: "cidr", Value: "10.255.255.0/24"}}, nil
		},
		warn: func(int64, string, string) { t.Error("strict 不应记 warn") },
	})
	gate := m.hostGate(taskID)
	err := gate(host)
	if err == nil {
		t.Fatal("strict 越界应拒绝")
	}
	want := fmt.Sprintf("RoE 授权范围检查：主机 %s 不在任务 %d 已登记范围内。如需放行：把目标加入任务范围(add_task_scope)，或调整 roe_enforcement 为 warn/off。", host, taskID)
	if err.Error() != want {
		t.Fatalf("gate = %q\nwant %q", err.Error(), want)
	}
	if err := gate("10.255.255.9"); err != nil {
		t.Fatalf("范围内应放行: %v", err)
	}
	if m.hostGate(0) != nil {
		t.Fatal("非任务运行不应安装 gate")
	}
}

func TestHostGateWarnAllowsAndNotifies(t *testing.T) {
	const taskID int64 = 8
	const host = "10.255.0.9"
	var notes []string
	m := &taskProxyManager{}
	m.useRoE(roeGateDeps{
		mode: func() string { return "warn" },
		scope: func(int64) ([]guard.ScopeRule, error) {
			return []guard.ScopeRule{{Kind: "domain", Value: "example.test"}}, nil
		},
		warn: func(gotTask int64, gotHost, msg string) {
			if gotTask != taskID || gotHost != host {
				t.Errorf("warn callback task=%d host=%s", gotTask, gotHost)
			}
			notes = append(notes, msg)
		},
	})
	gate := m.hostGate(taskID)
	if err := gate(host); err != nil {
		t.Fatalf("warn 应放行: %v", err)
	}
	if len(notes) != 1 || !strings.HasPrefix(notes[0], "⚠ ") || !strings.Contains(notes[0], host) || !strings.Contains(notes[0], "add_task_scope") || !strings.Contains(notes[0], "roe_enforcement") {
		t.Fatalf("warn notes = %#v", notes)
	}
	if err := gate("www.example.test"); err != nil || len(notes) != 1 {
		t.Fatalf("范围内不应告警: err=%v notes=%#v", err, notes)
	}
	if err := gate("  "); err != nil || len(notes) != 1 {
		t.Fatalf("空 host 应放行: err=%v notes=%#v", err, notes)
	}
	// warn-once: 同一 (taskID, host) 再次访问不再刷重复告警，不同 host 正常告警一次。
	if err := gate(host); err != nil || len(notes) != 1 {
		t.Fatalf("同一越界 host 应去重只告警一次: err=%v notes=%#v", err, notes)
	}
	m.roe.invalidate(taskID)
	if err := gate(host); err != nil || len(notes) != 2 {
		t.Fatalf("invalidate 后应重新告警一次: err=%v notes=%#v", err, notes)
	}
}

func TestHostGateOffSkipsScopeRead(t *testing.T) {
	calls := 0
	m := &taskProxyManager{}
	m.useRoE(roeGateDeps{
		mode: func() string { return "off" },
		scope: func(int64) ([]guard.ScopeRule, error) {
			calls++
			return nil, fmt.Errorf("off 不应读范围")
		},
		warn: func(int64, string, string) { t.Error("off 不应告警") },
	})
	if err := m.hostGate(3)("10.255.0.9"); err != nil {
		t.Fatalf("off 应放行: %v", err)
	}
	if err := m.hostGate(3)("10.255.0.9"); err != nil {
		t.Fatalf("off 缓存后应放行: %v", err)
	}
	if calls != 0 {
		t.Fatalf("off 读了 %d 次范围", calls)
	}
}

func TestHostGateStrictReadFailureDenies(t *testing.T) {
	const leak = "postgres://roe-user:roe-secret@10.1.2.3:5432/artex"
	m := &taskProxyManager{}
	m.useRoE(roeGateDeps{
		mode: func() string { return "strict" },
		scope: func(int64) ([]guard.ScopeRule, error) {
			return nil, fmt.Errorf("dial %s: connection refused", leak)
		},
	})
	err := m.hostGate(4)("10.255.0.9")
	if err == nil {
		t.Fatal("strict 读失败应拒绝")
	}
	got := err.Error()
	for _, want := range []string{"范围读取失败", "strict 拒绝", "warn/off", "10.255.0.9", "任务 4"} {
		if !strings.Contains(got, want) {
			t.Errorf("错误缺少 %q: %s", want, got)
		}
	}
	if strings.Contains(got, leak) || strings.Contains(got, "roe-secret") || strings.Contains(got, "postgres://") {
		t.Fatalf("错误泄露了读取失败细节: %s", got)
	}
}

func TestHostGateTTLAndInvalidate(t *testing.T) {
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	calls := 0
	tp := &taskProxyManager{}
	tp.useRoE(roeGateDeps{
		mode: func() string { return "strict" },
		scope: func(int64) ([]guard.ScopeRule, error) {
			calls++
			return []guard.ScopeRule{{Kind: "domain", Value: "example.test"}}, nil
		},
	})
	tp.roe.now = func() time.Time { return now }
	gate := tp.hostGate(9)
	if err := gate("10.255.0.9"); err == nil {
		t.Fatal("应拒绝")
	}
	if calls != 1 {
		t.Fatalf("首次 calls=%d", calls)
	}
	now = now.Add(4 * time.Second)
	if err := gate("10.255.0.9"); err == nil {
		t.Fatal("4s 内仍应拒绝")
	}
	if calls != 1 {
		t.Fatalf("4s 应命中缓存 calls=%d", calls)
	}
	now = now.Add(time.Second)
	if err := gate("10.255.0.9"); err == nil {
		t.Fatal("满 5s 后仍应拒绝")
	}
	if calls != 2 {
		t.Fatalf("恰好 5s 应重新读取 calls=%d", calls)
	}
	m := &Manager{taskProxy: tp}
	m.InvalidateProxyRoE(9)
	if err := gate("10.255.0.9"); err == nil {
		t.Fatal("失效后仍应拒绝")
	}
	if calls != 3 {
		t.Fatalf("失效后应重新读取 calls=%d", calls)
	}
}

func TestHostGateWarnRecordsActivity(t *testing.T) {
	pg := openTestPG(t)
	withRoEMode(t, pg, "warn")
	task, err := pg.CreateTask("roe host gate warn", "activity", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(task.ID) })
	if _, err := pg.Assets().AddAgentScope(task.ID, "root_domain", "example.test", "fixture", "manual"); err != nil {
		t.Fatalf("AddAgentScope: %v", err)
	}
	id := strconv.FormatInt(task.ID, 10)
	m := &Manager{
		pg: pg,
		tasks: map[string]*Task{
			id: {ID: id, Store: pg.Exploration(task.ExplorationID)},
		},
	}
	tp := &taskProxyManager{}
	tp.useRoE(m.proxyRoEDeps())
	host := "10.255.0.9"
	if err := tp.hostGate(task.ID)(host); err != nil {
		t.Fatalf("warn 应放行: %v", err)
	}
	var worker, kind, tool, summary, detail string
	err = pg.QueryRow(`SELECT COALESCE(worker,''), COALESCE(kind,''), COALESCE(tool,''), COALESCE(summary,''), COALESCE(detail,'')
		FROM activity WHERE exploration_id=$1 AND tool='roe' ORDER BY id DESC LIMIT 1`, task.ExplorationID).
		Scan(&worker, &kind, &tool, &summary, &detail)
	if err != nil {
		t.Fatalf("activity: %v", err)
	}
	if worker != "system" || kind != "text" || tool != "roe" {
		t.Fatalf("activity meta = %s/%s/%s", worker, kind, tool)
	}
	if !strings.HasPrefix(summary, "⚠ ") || summary != detail || !strings.Contains(summary, host) {
		t.Fatalf("activity text = %q / %q", summary, detail)
	}
}
