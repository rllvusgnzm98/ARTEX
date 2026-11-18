package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/session"
	actool "github.com/Autumn-27/norma/tool"
)

// reconFixtureSession 不连真实目标：按 recon 命令包关键字返回固定多样本输出。
type reconFixtureSession struct{ id int64 }

func (f *reconFixtureSession) ID() int64                  { return f.id }
func (f *reconFixtureSession) Kind() string               { return "http_php" }
func (f *reconFixtureSession) Test(context.Context) error { return nil }
func (f *reconFixtureSession) Exec(_ context.Context, cmd string, _ time.Duration) (string, string, error) {
	switch {
	case strings.Contains(cmd, "addr") || strings.Contains(cmd, "ifconfig"):
		return reconFixtureNICs, "", nil
	case strings.Contains(cmd, "route"):
		return reconFixtureRoutes, "", nil
	case strings.Contains(cmd, "neigh") || strings.Contains(cmd, "arp"):
		return reconFixtureNeighbors, "", nil
	case strings.Contains(cmd, "hosts"):
		return reconFixtureHosts, "", nil
	case strings.Contains(cmd, "ss ") || strings.Contains(cmd, "netstat"):
		return reconFixtureConns, "", nil
	default:
		return "", "", nil
	}
}
func (f *reconFixtureSession) ReadFile(context.Context, string) ([]byte, error) {
	return nil, nil
}
func (f *reconFixtureSession) WriteFile(context.Context, string, []byte) error { return nil }
func (f *reconFixtureSession) Close(context.Context) error                     { return nil }

// 两台可见主机：本机 192.168.1.10 与 10.0.0.5，邻居 192.168.1.1 / 10.0.0.7，对端 10.8.0.5。
const reconFixtureNICs = `1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 192.168.1.10/24 brd 192.168.1.255 scope global dynamic eth0
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth1
`
const reconFixtureRoutes = `default via 192.168.1.1 dev eth0 proto dhcp
172.16.0.0/16 via 10.0.0.1 dev eth1
`
const reconFixtureNeighbors = `192.168.1.1 dev eth0 lladdr 08:00:27:11:22:33 REACHABLE
10.0.0.7 dev eth1 lladdr 08:00:27:44:55:66 STALE
`
const reconFixtureHosts = `127.0.0.1 localhost
10.0.0.5 web01
`
const reconFixtureConns = `tcp  LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
tcp  ESTAB  0   0 10.0.0.5:445 10.8.0.5:51234
`

var _ session.Session = (*reconFixtureSession)(nil)

func TestSessionReconWritesAssetsFactsAndEntrySeed(t *testing.T) {
	pg := openIntranetTestDB(t)
	task, err := pg.CreateTask("foothold recon fixture", "read confirmed hosts", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(task.ID) })

	assets := pg.Assets()
	if _, err := assets.AddAgentScope(task.ID, "cidr", "192.168.1.0/24", "fixture in-scope", "manual"); err != nil {
		t.Fatalf("seed task_scope: %v", err)
	}

	store := db.NewSessionStore(pg, []byte("recon-fixture-master-key"))
	ctx := context.Background()
	sessID, err := store.Create(ctx, &db.SessionRecord{
		Kind: "http_php", URL: "http://192.168.1.10/s.php", Lang: "php",
		Status: db.SessionAlive, CreatedByTask: task.ID,
		Secret: json.RawMessage(`{"url":"http://192.168.1.10/s.php"}`),
	})
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	t.Cleanup(func() { _ = store.Delete(context.Background(), sessID) })

	s := &Server{
		m:         &Manager{pg: pg, assets: assets},
		sessStore: store,
		sessReg:   session.NewRegistry(),
		ctx:       ctx,
	}
	s.sessReg.Add(&reconFixtureSession{id: sessID})

	es := pg.Exploration(task.ExplorationID)
	intentID, err := es.AddIntent(map[string]any{"summary": "continue from confirmed hosts"}, 5, nil, "planner")
	if err != nil {
		t.Fatalf("AddIntent: %v", err)
	}
	intent, err := es.GetNode(intentID)
	if err != nil || intent == nil {
		t.Fatalf("GetNode intent: %v", intent)
	}

	runCtx := agent.WithRunInfo(ctx, agent.RunInfo{
		TaskID: task.ID, ExplorationID: task.ExplorationID, IntentID: intentID,
	})
	tool := s.sessionReconTool()
	in, _ := json.Marshal(map[string]any{"session_id": sessID})
	res, err := tool.Call(runCtx, in, &actool.ToolContext{})
	if err != nil {
		t.Fatalf("session_recon: %v", err)
	}
	out := toolResultJSON(t, res)
	if _, ok := out["fact_id"]; !ok {
		t.Fatalf("应写回 fact: %v", out)
	}

	ips, err := assets.QueryByTask(task.ID, "ip", 100, 0)
	if err != nil {
		t.Fatalf("QueryByTask: %v", err)
	}
	gotIP := map[string]bool{}
	labels := map[int64]string{}
	for _, a := range ips {
		gotIP[a.IP] = true
		labels[a.ID] = a.IP
	}
	for _, want := range []string{"192.168.1.10", "10.0.0.5", "192.168.1.1", "10.0.0.7", "10.8.0.5"} {
		if !gotIP[want] {
			t.Errorf("资产图缺少主机 %s (got %v)", want, gotIP)
		}
	}

	pending, err := assets.ListPendingScope(task.ID, true)
	if err != nil {
		t.Fatalf("ListPendingScope: %v", err)
	}
	pendingVal := map[string]string{}
	for _, p := range pending {
		pendingVal[p.Value] = p.Status
	}
	if pendingVal["10.0.0.0/24"] != "pending" {
		t.Errorf("出界 10.0.0.0/24 应登记 pending: %+v", pending)
	}
	if pendingVal["10.8.0.0/24"] != "pending" {
		t.Errorf("出界 10.8.0.0/24 应登记 pending: %+v", pending)
	}
	if _, ok := pendingVal["192.168.1.0/24"]; ok {
		t.Errorf("已在 scope 内的 192.168.1.0/24 不应进 pending: %+v", pending)
	}

	// 下一跳意图从该侦察事实 derived_from 出发：进场预塞应按父事实读到已确认主机。
	factID := int64(out["fact_id"].(float64))
	nextID, err := es.AddIntent(map[string]any{"summary": "continue confirmed hosts"}, 5, nil, "planner")
	if err != nil {
		t.Fatalf("next intent: %v", err)
	}
	if err := es.Link(factID, db.RelDerivedFrom, nextID); err != nil {
		t.Fatalf("link derived_from: %v", err)
	}
	next, err := es.GetNode(nextID)
	if err != nil || next == nil {
		t.Fatalf("GetNode next intent: %v", err)
	}

	seed := agent.LoadWorkerEntrySeed(es, assets, next)
	if len(seed.Writes) != 0 {
		t.Fatalf("进场预塞必须只读, writes=%v", seed.Writes)
	}
	found := false
	for _, f := range seed.ConfirmedFacts {
		if strings.Contains(f.Summary, "内网被动侦察") || strings.Contains(f.Detail, "192.168.1.10") || strings.Contains(f.Summary, "session") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("BuildWorkerEntrySeed / 进场预塞未读到侦察确认事实: %+v reasons=%v", seed.ConfirmedFacts, seed.IncompleteReasons)
	}
	prompt := agent.RenderWorkerEntrySeed(seed)
	if !strings.Contains(prompt, "192.168.1") && !strings.Contains(prompt, "10.0.0") && !strings.Contains(prompt, "侦察") {
		t.Fatalf("预塞正文应包含已确认主机或侦察摘要:\n%s", prompt)
	}
}

func toolResultJSON(t *testing.T, res actool.Result) map[string]any {
	t.Helper()
	if res.IsError {
		t.Fatalf("tool error: %s", res.Flatten())
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("tool JSON: %v (%s)", err, res.Flatten())
	}
	return out
}
