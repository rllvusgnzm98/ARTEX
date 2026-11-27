package server

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestHasLiveTaskSessionNilSafe(t *testing.T) {
	if hasLiveTaskSession(nil, errors.New("list failed"), 1) {
		t.Fatal("查找失败不得误切内网变体")
	}
	if hasLiveTaskSession(nil, nil, 1) {
		t.Fatal("无记录应为外网")
	}
	if hasLiveTaskSession([]*db.SessionRecord{{CreatedByTask: 2, Status: db.SessionAlive}}, nil, 1) {
		t.Fatal("其他任务的存活会话不得切本任务变体")
	}
	if hasLiveTaskSession([]*db.SessionRecord{{CreatedByTask: 1, Status: db.SessionAlive}}, nil, 0) {
		t.Fatal("非法 taskID 不得切变体")
	}
	if !hasLiveTaskSession([]*db.SessionRecord{{CreatedByTask: 3, Status: db.SessionAlive}}, nil, 3) {
		t.Fatal("本任务存活会话应切内网变体")
	}
}

func TestTaskIntranetNilStoreAndNoTunnelsStayExternal(t *testing.T) {
	var s Server
	if s.taskIntranet(1) {
		t.Fatal("sessStore 为 nil 且无隧道台账时必须保持外网")
	}
	if s.taskIntranet(0) {
		t.Fatal("非法 taskID 必须保持外网")
	}
}

func TestTaskIntranetLiveSessionOnly(t *testing.T) {
	pg := openIntranetTestDB(t)
	task, err := pg.CreateTask("intranet variant fixture", "live session check", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(task.ID) })
	other, err := pg.CreateTask("other task", "unrelated", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask other: %v", err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(other.ID) })

	store := db.NewSessionStore(pg, []byte("intranet-variant-master-key"))
	s := &Server{ctx: context.Background(), sessStore: store}

	if s.taskIntranet(task.ID) {
		t.Fatal("尚无会话时应为外网")
	}

	ctx := context.Background()
	deadID, err := store.Create(ctx, &db.SessionRecord{
		Kind: "http_php", URL: "http://192.0.2.10/s.php", Lang: "php",
		Status: db.SessionDead, CreatedByTask: task.ID,
		Secret: json.RawMessage(`{"url":"http://192.0.2.10/s.php"}`),
	})
	if err != nil {
		t.Fatalf("Create dead: %v", err)
	}
	t.Cleanup(func() { _ = store.Delete(context.Background(), deadID) })
	if s.taskIntranet(task.ID) {
		t.Fatal("仅有 dead 会话不得切内网变体")
	}

	aliveOther, err := store.Create(ctx, &db.SessionRecord{
		Kind: "http_php", URL: "http://192.0.2.11/s.php", Lang: "php",
		Status: db.SessionAlive, CreatedByTask: other.ID,
		Secret: json.RawMessage(`{"url":"http://192.0.2.11/s.php"}`),
	})
	if err != nil {
		t.Fatalf("Create other alive: %v", err)
	}
	t.Cleanup(func() { _ = store.Delete(context.Background(), aliveOther) })
	if s.taskIntranet(task.ID) {
		t.Fatal("其他任务的存活会话不得切本任务变体")
	}

	aliveID, err := store.Create(ctx, &db.SessionRecord{
		Kind: "http_php", URL: "http://192.0.2.12/s.php", Lang: "php",
		Status: db.SessionAlive, CreatedByTask: task.ID,
		Secret: json.RawMessage(`{"url":"http://192.0.2.12/s.php"}`),
	})
	if err != nil {
		t.Fatalf("Create alive: %v", err)
	}
	t.Cleanup(func() { _ = store.Delete(context.Background(), aliveID) })
	if !s.taskIntranet(task.ID) {
		t.Fatal("本任务存活立足点会话应切内网变体")
	}
}

type fakeTunnelLiveLister struct {
	recs []*db.TunnelRecord
	err  error
}

func (f *fakeTunnelLiveLister) ListByTask(context.Context, int64) ([]*db.TunnelRecord, error) {
	return f.recs, f.err
}

func TestHasLiveTaskTunnelNilSafe(t *testing.T) {
	if hasLiveTaskTunnel(nil, errors.New("list failed")) {
		t.Fatal("查找失败不得误切内网变体")
	}
	if hasLiveTaskTunnel(nil, nil) {
		t.Fatal("无记录应为外网")
	}
	if hasLiveTaskTunnel([]*db.TunnelRecord{{TaskID: 1, State: db.TunnelStopped}}, nil) {
		t.Fatal("stopped 隧道不得切内网变体")
	}
	if !hasLiveTaskTunnel([]*db.TunnelRecord{{TaskID: 1, State: db.TunnelAlive}}, nil) {
		t.Fatal("存活隧道应切内网变体")
	}
}

func TestTaskIntranetLiveTunnelSwitchesAndLookupFailureStaysExternal(t *testing.T) {
	s := &Server{ctx: context.Background()}
	if s.taskIntranet(9) {
		t.Fatal("无台账时应保持外网")
	}
	s.tunnelLive = &fakeTunnelLiveLister{err: errors.New("lookup failed")}
	if s.taskIntranet(9) {
		t.Fatal("台账查找失败必须保持外网变体")
	}
	s.tunnelLive = &fakeTunnelLiveLister{recs: []*db.TunnelRecord{{TaskID: 9, State: db.TunnelError}}}
	if s.taskIntranet(9) {
		t.Fatal("非 alive 隧道不得切内网变体")
	}
	s.tunnelLive = &fakeTunnelLiveLister{recs: []*db.TunnelRecord{{TaskID: 9, State: db.TunnelAlive}}}
	if !s.taskIntranet(9) {
		t.Fatal("本任务存活隧道应切内网变体")
	}
}

func TestTaskIntranetDBRegisteredTunnelsAndLogicalSessions(t *testing.T) {
	pg := openIntranetTestDB(t)
	task, err := pg.CreateTask("intranet db tunnel test", "tunnel_register activates intranet", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	store := db.NewTunnelStore(pg)
	t.Cleanup(func() {
		recs, _ := store.ListByTask(context.Background(), task.ID)
		for _, r := range recs {
			_ = store.Delete(context.Background(), r.ID)
		}
		_ = pg.DeleteTask(task.ID)
	})

	// Even when s.tunnelLive is nil, taskIntranet checks s.tunnels.store and s.m.pg.
	sNoLive := &Server{ctx: context.Background(), tunnels: &tunnelRuntime{store: store}}
	sPGOnly := &Server{ctx: context.Background(), m: &Manager{pg: pg}}
	if sNoLive.taskIntranet(task.ID) || sPGOnly.taskIntranet(task.ID) {
		t.Fatal("无隧道时必须保持外网")
	}

	tid, err := store.Create(context.Background(), &db.TunnelRecord{
		TaskID: task.ID, Kind: "portfwd", Adapter: "external",
		ListenHost: "127.0.0.1", ListenPort: 18888,
		TargetHost: "10.0.0.5", TargetPort: 445,
		State: db.TunnelAlive,
	})
	if err != nil {
		t.Fatalf("Create tunnel: %v", err)
	}
	if !sNoLive.taskIntranet(task.ID) {
		t.Fatal("DB 登记的 alive 隧道应 via s.tunnels.store 激活 taskIntranet")
	}
	if !sPGOnly.taskIntranet(task.ID) {
		t.Fatal("DB 登记的 alive 隧道应 via s.m.pg 激活 taskIntranet")
	}

	if err := store.UpdateState(context.Background(), tid, db.TunnelStopped, ""); err != nil {
		t.Fatalf("UpdateState stopped: %v", err)
	}
	if sNoLive.taskIntranet(task.ID) || sPGOnly.taskIntranet(task.ID) {
		t.Fatal("stopped 隧道不应激活 taskIntranet")
	}

	// Logical sessions integrate cleanly in hasLiveTaskSession and buildTopology.
	for _, kind := range []string{"winrm", "ssh", "msf_bind"} {
		if !hasLiveTaskSession([]*db.SessionRecord{{CreatedByTask: task.ID, Kind: kind, Status: db.SessionAlive}}, nil, task.ID) {
			t.Fatalf("alive logical session kind=%s should activate taskIntranet", kind)
		}
		if hasLiveTaskSession([]*db.SessionRecord{{CreatedByTask: task.ID, Kind: kind, Status: db.SessionDead}}, nil, task.ID) {
			t.Fatalf("dead logical session kind=%s must not activate taskIntranet", kind)
		}
	}
	topo := buildTopology(nil, []*db.SessionRecord{
		{ID: 501, Kind: "ssh", URL: "ssh://10.20.30.40:22", Status: db.SessionAlive, CreatedByTask: task.ID},
		{ID: 502, Kind: "winrm", URL: "", Secret: json.RawMessage(`{"host":"10.20.30.41","port":5985}`), Status: db.SessionAlive, CreatedByTask: task.ID},
	}, []topoTunnel{
		{ID: 601, Kind: "portfwd", TargetHost: "10.20.30.40", TargetPort: 22, State: db.TunnelAlive},
	}, "203.0.113.5")
	nodes := topo["nodes"].([]*topoNode)
	seenIP := map[string]*topoNode{}
	for _, n := range nodes {
		seenIP[n.IP] = n
	}
	if seenIP["10.20.30.40"] == nil || !seenIP["10.20.30.40"].HasSession || seenIP["10.20.30.40"].AliveSessions != 1 {
		t.Fatalf("topology missing ssh logical session node: %+v", nodes)
	}
	if seenIP["10.20.30.41"] == nil || !seenIP["10.20.30.41"].HasSession {
		t.Fatalf("topology missing winrm Secret.host fallback node: %+v", nodes)
	}
}
