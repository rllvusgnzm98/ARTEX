package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/session"
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
