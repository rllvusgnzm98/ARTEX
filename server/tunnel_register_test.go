package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

func TestTunnelRegisterWiredAndSeeded(t *testing.T) {
	pg := openIntranetTestDB(t)
	s := &Server{
		m:       &Manager{pg: pg},
		tunnels: &tunnelRuntime{store: db.NewTunnelStore(pg)},
	}
	toolMap := names(s.tunnelTools())
	regTool, ok := toolMap["tunnel_register"]
	if !ok {
		t.Fatal("tunnelTools() must include tunnel_register")
	}
	s.seedTunnelTools()
	row, err := pg.GetTool("tunnel_register")
	if err != nil || row == nil {
		t.Fatalf("seedTunnelTools did not persist tunnel_register: %v", err)
	}
	if row.Description != regTool.Description() {
		t.Fatalf("seeded description mismatch: %q vs %q", row.Description, regTool.Description())
	}
	hasWorker := false
	for _, a := range row.Agents {
		if a == "worker" {
			hasWorker = true
			break
		}
	}
	if !hasWorker {
		t.Fatalf("tunnel_register should be bound to worker by default, got %v", row.Agents)
	}
}

func TestTunnelRegisterSocksAndPortfwdDedup(t *testing.T) {
	pg := openIntranetTestDB(t)
	taskA, err := pg.CreateTask("tunnel register A", "verify dedup", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask A: %v", err)
	}
	taskB, err := pg.CreateTask("tunnel register B", "verify task isolation", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask B: %v", err)
	}
	store := db.NewTunnelStore(pg)
	t.Cleanup(func() {
		for _, tid := range []int64{taskA.ID, taskB.ID} {
			recs, _ := store.ListByTask(context.Background(), tid)
			for _, r := range recs {
				_ = store.Delete(context.Background(), r.ID)
			}
			_ = pg.DeleteTask(tid)
		}
	})

	s := &Server{
		m:       &Manager{pg: pg},
		tunnels: &tunnelRuntime{store: store},
	}
	regTool := s.tunnelRegisterTool()
	listTool := s.tunnelListTool()
	ctxA := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: taskA.ID})
	ctxB := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: taskB.ID})

	// 1. Register SOCKS5 proxy for task A.
	in1, _ := json.Marshal(map[string]any{
		"listen_addr": "127.0.0.1:10808",
		"protocol":    "socks5",
		"notes":       "ssh -D 10808 jumpbox",
	})
	res1, err := regTool.Call(ctxA, in1, &actool.ToolContext{})
	if err != nil || res1.IsError {
		t.Fatalf("register socks failed: err=%v body=%s", err, res1.Flatten())
	}
	out1 := toolResultJSON(t, res1)
	id1 := int64(out1["tunnel_id"].(float64))
	if out1["kind"] != "socks" || out1["state"] != db.TunnelAlive || out1["deduplicated"] != false {
		t.Fatalf("unexpected first register result: %+v", out1)
	}

	// 2. Re-register same (task_id, listen_addr, target_addr) using scheme prefix -> deduplicates & updates.
	in2, _ := json.Marshal(map[string]any{
		"listen_addr": "socks5://127.0.0.1:10808",
		"protocol":    "socks5",
		"state":       "stopped",
		"notes":       "updated socks note",
	})
	res2, err := regTool.Call(ctxA, in2, &actool.ToolContext{})
	if err != nil || res2.IsError {
		t.Fatalf("re-register socks failed: err=%v body=%s", err, res2.Flatten())
	}
	out2 := toolResultJSON(t, res2)
	if int64(out2["tunnel_id"].(float64)) != id1 || out2["deduplicated"] != true || out2["updated"] != true {
		t.Fatalf("expected dedup update on tunnel_id=%d, got %+v", id1, out2)
	}
	rec1, err := store.Get(context.Background(), id1)
	if err != nil || rec1 == nil || rec1.State != db.TunnelStopped {
		t.Fatalf("expected updated state=stopped, got %+v err=%v", rec1, err)
	}
	if !strings.Contains(string(rec1.DeployParams), "updated socks note") {
		t.Fatalf("expected updated notes in deploy_params: %s", string(rec1.DeployParams))
	}

	// 3. Register portfwd for task A + deduplicate it.
	in3, _ := json.Marshal(map[string]any{
		"listen_addr": "127.0.0.1:18443",
		"target_addr": "10.10.20.5:8443",
		"protocol":    "chisel",
		"notes":       "internal admin panel",
	})
	res3, err := regTool.Call(ctxA, in3, &actool.ToolContext{})
	if err != nil || res3.IsError {
		t.Fatalf("register portfwd failed: err=%v body=%s", err, res3.Flatten())
	}
	out3 := toolResultJSON(t, res3)
	id3 := int64(out3["tunnel_id"].(float64))
	if out3["kind"] != "portfwd" || out3["target_addr"] != "10.10.20.5:8443" {
		t.Fatalf("unexpected portfwd result: %+v", out3)
	}
	res3Dup, err := regTool.Call(ctxA, in3, &actool.ToolContext{})
	if err != nil || res3Dup.IsError {
		t.Fatalf("dedup portfwd failed: err=%v body=%s", err, res3Dup.Flatten())
	}
	out3Dup := toolResultJSON(t, res3Dup)
	if int64(out3Dup["tunnel_id"].(float64)) != id3 || out3Dup["deduplicated"] != true {
		t.Fatalf("expected portfwd dedup on %d, got %+v", id3, out3Dup)
	}

	// 4. Same listen_addr/target_addr under task B creates a distinct row.
	resB, err := regTool.Call(ctxB, in3, &actool.ToolContext{})
	if err != nil || resB.IsError {
		t.Fatalf("register task B failed: err=%v body=%s", err, resB.Flatten())
	}
	outB := toolResultJSON(t, resB)
	if int64(outB["tunnel_id"].(float64)) == id3 || outB["deduplicated"] != false {
		t.Fatalf("different task_id must not dedup with task A: %+v", outB)
	}

	// Verify task A has exactly 2 rows and tunnel_list exposes them.
	recsA, err := store.ListByTask(context.Background(), taskA.ID)
	if err != nil || len(recsA) != 2 {
		t.Fatalf("task A tunnel count = %d, want 2 (err=%v)", len(recsA), err)
	}
	listRes, err := listTool.Call(ctxA, []byte(`{}`), &actool.ToolContext{})
	if err != nil || listRes.IsError {
		t.Fatalf("tunnel_list failed: err=%v body=%s", err, listRes.Flatten())
	}
	listOut := toolResultJSON(t, listRes)
	if int(listOut["count"].(float64)) != 2 {
		t.Fatalf("tunnel_list count=%v, want 2", listOut["count"])
	}
}
