package db

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestTunnelStoreCRUD(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()
	s := NewTunnelStore(d)

	taskID := time.Now().UnixNano()
	params, _ := json.Marshal(map[string]any{
		"auth_user": "artex", "auth_pass": "fixture-pass",
		"server_pid": 0, "socks_port": 20002, "stage_token": "fixture-token",
	})
	id, err := s.Create(ctx, &TunnelRecord{
		TaskID: taskID, Kind: "socks", ListenHost: "127.0.0.1", ListenPort: 20001,
		ViaSessionID: 3, State: TunnelDeploying, DeployParams: params,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(context.Background(), id) })

	rec, err := s.Get(ctx, id)
	if err != nil || rec == nil {
		t.Fatalf("Get: %v rec=%v", err, rec)
	}
	if rec.State != TunnelDeploying || rec.ListenPort != 20001 || rec.Adapter != "chisel" {
		t.Errorf("行内容不符: %+v", rec)
	}
	var p map[string]any
	if err := json.Unmarshal(rec.DeployParams, &p); err != nil || p["auth_pass"] != "fixture-pass" {
		t.Errorf("deploy_params 往返失败: %v %v", err, p)
	}

	if err := s.UpdateState(ctx, id, TunnelAlive, ""); err != nil {
		t.Fatalf("UpdateState: %v", err)
	}
	if err := s.UpdateState(ctx, id, "bogus", ""); err == nil {
		t.Error("非法状态应报错")
	}
	alive, err := s.ListAlive(ctx)
	if err != nil {
		t.Fatalf("ListAlive: %v", err)
	}
	found := false
	for _, r := range alive {
		if r.ID == id {
			found = true
		}
	}
	if !found {
		t.Error("ListAlive 未含新隧道")
	}

	byTask, err := s.ListByTask(ctx, taskID)
	if err != nil || len(byTask) != 1 {
		t.Errorf("ListByTask = %d 行, %v", len(byTask), err)
	}

	params2, _ := json.Marshal(map[string]any{"remote_pid": 0, "note": "fixture"})
	if err := s.UpdateDeployParams(ctx, id, 0, params2); err != nil {
		t.Fatalf("UpdateDeployParams: %v", err)
	}
	rec, _ = s.Get(ctx, id)
	if rec == nil {
		t.Fatal("Get after UpdateDeployParams")
	}

	if _, err := s.Create(ctx, &TunnelRecord{TaskID: taskID, Kind: "gre"}); err == nil {
		t.Error("非法 kind 应报错")
	}

	if err := s.Delete(ctx, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	rec, _ = s.Get(ctx, id)
	if rec != nil {
		t.Error("Delete 后 Get 应为 nil")
	}
}
