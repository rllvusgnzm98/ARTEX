package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/session"
	"github.com/Autumn-27/artex/tunnel"
	actool "github.com/Autumn-27/norma/tool"
)

func TestRoETunnelDeployPortfwdStrictRejects(t *testing.T) {
	_, task, s := roeFixture(t, "strict")
	store := db.NewTunnelStore(s.m.pg)
	s.tunnels = &tunnelRuntime{store: store, dataDir: t.TempDir()}
	s.sessReg = session.NewRegistry()
	const sessID int64 = 424242
	s.sessReg.Add(&reconFixtureSession{id: sessID})
	t.Cleanup(func() {
		recs, err := store.ListByTask(context.Background(), task.ID)
		if err != nil {
			return
		}
		for _, rec := range recs {
			_ = store.Delete(context.Background(), rec.ID)
		}
	})
	t.Setenv("ARTEX_CALLBACK_ADDR", "203.0.113.10:4444")

	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: task.ID})
	tool := s.tunnelDeployTool()
	in, _ := json.Marshal(map[string]any{
		"session_id": sessID,
		"kind":       "portfwd",
		"target":     "10.255.0.9:8443",
	})
	res, err := tool.Call(ctx, in, &actool.ToolContext{})
	if err != nil {
		t.Fatalf("tunnel_deploy: %v", err)
	}
	text := res.Flatten()
	if !res.IsError || !strings.Contains(text, "RoE 授权范围检查") || !strings.Contains(text, "隧道目标 10.255.0.9") {
		t.Fatalf("strict 越界应拒绝: %s", text)
	}
	if strings.Contains(text, "计划生成失败") || strings.Contains(text, "隧道运行时未就绪") || strings.Contains(text, "部署失败") {
		t.Fatalf("应在部署前以 RoE 文案拒绝: %s", text)
	}
}

func TestRoETunnelDeployWarnFailureKeepsWarning(t *testing.T) {
	pg, task, s := roeFixture(t, "warn")
	id := strconv.FormatInt(task.ID, 10)
	s.m.tasks = map[string]*Task{
		id: {ID: id, Store: pg.Exploration(task.ExplorationID)},
	}
	store := db.NewTunnelStore(s.m.pg)
	mgr, err := tunnel.NewManager(tunnel.Options{Store: failCreateStore{}, DataDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	s.tunnels = &tunnelRuntime{store: store, dataDir: t.TempDir(), mgr: mgr}
	s.sessReg = session.NewRegistry()
	const sessID int64 = 424243
	s.sessReg.Add(&reconFixtureSession{id: sessID})
	t.Cleanup(func() {
		recs, lerr := store.ListByTask(context.Background(), task.ID)
		if lerr != nil {
			return
		}
		for _, rec := range recs {
			_ = store.Delete(context.Background(), rec.ID)
		}
	})
	t.Setenv("ARTEX_CALLBACK_ADDR", "203.0.113.10:4444")

	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: task.ID})
	tool := s.tunnelDeployTool()
	in, _ := json.Marshal(map[string]any{
		"session_id": sessID,
		"kind":       "portfwd",
		"target":     "10.255.0.9:8443",
	})
	res, err := tool.Call(ctx, in, &actool.ToolContext{})
	if err != nil {
		t.Fatalf("tunnel_deploy: %v", err)
	}
	text := res.Flatten()
	if !res.IsError || !strings.Contains(text, "部署失败") {
		t.Fatalf("部署失败应返回错误: %s", text)
	}
	if !strings.Contains(text, "⚠") || !strings.Contains(text, "RoE 授权范围检查") || !strings.Contains(text, "隧道目标 10.255.0.9") {
		t.Fatalf("部署失败仍应带上越界告警: %s", text)
	}
	if strings.Index(text, "RoE 授权范围检查") > strings.Index(text, "部署失败") {
		t.Fatalf("告警应出现在部署失败之前: %s", text)
	}
	var summary string
	err = pg.QueryRow(`SELECT COALESCE(summary,'') FROM activity WHERE exploration_id=$1 AND tool='roe' ORDER BY id DESC LIMIT 1`, task.ExplorationID).Scan(&summary)
	if err != nil {
		t.Fatalf("部署失败后 activity 里没有 RoE 告警: %v", err)
	}
	if !strings.Contains(summary, "⚠") || !strings.Contains(summary, "10.255.0.9") {
		t.Fatalf("activity = %q", summary)
	}
}

// failCreateStore 让 Deploy 在写台账时失败并返回 nil 记录，从而走到「部署失败」分支。
type failCreateStore struct{}

func (failCreateStore) Create(context.Context, *db.TunnelRecord) (int64, error) {
	return 0, fmt.Errorf("injected create failure")
}
func (failCreateStore) Get(context.Context, int64) (*db.TunnelRecord, error) { return nil, nil }
func (failCreateStore) UpdateState(context.Context, int64, string, string) error {
	return nil
}
func (failCreateStore) UpdateDeployParams(context.Context, int64, int, json.RawMessage) error {
	return nil
}
func (failCreateStore) Delete(context.Context, int64) error { return nil }
func (failCreateStore) ListByTask(context.Context, int64) ([]*db.TunnelRecord, error) {
	return nil, nil
}
func (failCreateStore) ListAlive(context.Context) ([]*db.TunnelRecord, error) {
	return nil, nil
}
func (failCreateStore) ListActive(context.Context) ([]*db.TunnelRecord, error) {
	return nil, nil
}
func (failCreateStore) List(context.Context) ([]*db.TunnelRecord, error) { return nil, nil }
