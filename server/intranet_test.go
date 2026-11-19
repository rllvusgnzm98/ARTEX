package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/session"
)

func TestParseLsLa(t *testing.T) {
	out := `total 48
drwxr-xr-x  5 root root 4096 Sep 12 10:00 .
drwxr-xr-x 22 root root 4096 Sep  1 08:00 ..
-rw-r--r--  1 root root  220 Sep 10  2023 .bash_logout
-rw-r--r--  1 root root 3771 Sep 10  2023 .bashrc
drwxr-xr-x  2 root root 4096 Aug 30 11:11 my dir
lrwxrwxrwx  1 root root   11 Sep 12 09:59 link -> /etc/passwd
-rw-------  1 www-data www-data 123456 Sep 12 12:00 dump.sql
not a valid line at all
`
	entries := parseLsLa(out)
	if len(entries) != 5 {
		t.Fatalf("期望 5 条,实得 %d: %+v", len(entries), entries)
	}
	byName := map[string]dirEntry{}
	for _, e := range entries {
		byName[e.Name] = e
	}
	if e, ok := byName[".bashrc"]; !ok || e.IsDir || e.Size != 3771 {
		t.Errorf(".bashrc 解析错误: %+v", e)
	}
	if e, ok := byName["my dir"]; !ok || !e.IsDir || e.Size != 4096 {
		t.Errorf("带空格目录解析错误: %+v", e)
	}
	if e, ok := byName["link"]; !ok || e.IsDir || e.Size != 11 {
		t.Errorf("symlink 应去掉 -> target 且非目录: %+v", e)
	}
	if e, ok := byName["dump.sql"]; !ok || e.IsDir || e.Size != 123456 {
		t.Errorf("dump.sql 解析错误: %+v", e)
	}
	if _, ok := byName["."]; ok {
		t.Error(". 应被跳过")
	}
	if _, ok := byName[".."]; ok {
		t.Error(".. 应被跳过")
	}
}

func TestParseLsLaEmpty(t *testing.T) {
	if got := parseLsLa(""); len(got) != 0 {
		t.Fatalf("空输出应得空列表: %+v", got)
	}
	if got := parseLsLa("total 0\n"); len(got) != 0 {
		t.Fatalf("仅 total 行应得空列表: %+v", got)
	}
}

func TestSegmentOf(t *testing.T) {
	if got := segmentOf("10.0.0.5", "192.168.1.0/24"); got != "192.168.1.0/24" {
		t.Errorf("c_segment 优先: %s", got)
	}
	if got := segmentOf("10.0.0.5", ""); got != "10.0.0.0/24" {
		t.Errorf("IPv4 /24 推导: %s", got)
	}
	if got := segmentOf("not-an-ip", ""); got != "" {
		t.Errorf("非法 IP 应空: %q", got)
	}
}

func TestBuildTopology(t *testing.T) {
	assets := []*db.Asset{
		{ID: 1, IP: "10.0.0.5", CSegment: "10.0.0.0/24",
			OpenPorts: []map[string]any{{"port": float64(22), "service": "ssh"}, {"port": float64(80)}}},
		{ID: 2, IP: "10.0.1.7"},
	}
	recs := []*db.SessionRecord{
		{ID: 11, HostAssetID: 1, URL: "http://10.0.0.5/s.php", Status: db.SessionAlive, CreatedByTask: 3},
		{ID: 12, URL: "http://10.0.9.9:8080/s.jsp", Status: db.SessionAlive, CreatedByTask: 3},
		{ID: 13, HostAssetID: 2, URL: "http://10.0.1.7/x.php", Status: db.SessionDead, CreatedByTask: 3},
	}
	topo := buildTopology(assets, recs, nil, "")

	nodes := topo["nodes"].([]*topoNode)
	// 2 资产 + 1 合成 sess（无资产关联的 10.0.9.9）；无隧道时不造 platform 节点。
	if len(nodes) != 3 {
		t.Fatalf("节点数应为 3: %d", len(nodes))
	}
	byID := map[string]*topoNode{}
	for _, n := range nodes {
		byID[n.ID] = n
	}
	n5 := byID["asset-1"]
	if n5 == nil || !n5.HasSession || n5.AliveSessions != 1 {
		t.Errorf("10.0.0.5 节点错误: %+v", n5)
	}
	if len(n5.Services) != 2 {
		t.Errorf("services 应 2 条: %+v", n5.Services)
	}
	n7 := byID["asset-2"]
	if n7 == nil || !n7.HasSession || n7.AliveSessions != 0 {
		t.Errorf("dead 会话主机应 has_session=true 但 alive=0: %+v", n7)
	}
	n9 := byID["sess-12"]
	if n9 == nil || n9.IP != "10.0.9.9" || n9.Segment != "10.0.9.0/24" {
		t.Errorf("合成节点错误: %+v", n9)
	}
	if _, ok := byID["platform"]; ok {
		t.Errorf("无隧道时不应出现 platform 节点")
	}
	if edges := topo["edges"].([]topoEdge); len(edges) != 0 {
		t.Errorf("无隧道时边应为空: %+v", edges)
	}
	segs := topo["segments"].([]topoSegment)
	if len(segs) != 3 {
		t.Fatalf("网段数应 3: %+v", segs)
	}
	if segs[0].Name != "10.0.0.0/24" {
		t.Errorf("网段排序错误: %+v", segs)
	}
	if _, err := json.Marshal(topo); err != nil {
		t.Fatalf("拓扑 JSON 序列化失败: %v", err)
	}
}

func TestBuildTopologyEmpty(t *testing.T) {
	topo := buildTopology(nil, nil, nil, "")
	if len(topo["nodes"].([]*topoNode)) != 0 ||
		len(topo["edges"].([]topoEdge)) != 0 ||
		len(topo["segments"].([]topoSegment)) != 0 {
		t.Fatalf("空输入应得空拓扑: %+v", topo)
	}
}

func TestBuildTopologyTaskFilter(t *testing.T) {
	assetsA := []*db.Asset{{ID: 1, IP: "10.20.0.1", CSegment: "10.20.0.0/24"}}
	assetsB := []*db.Asset{{ID: 2, IP: "10.21.0.1", CSegment: "10.21.0.0/24"}}
	recs := []*db.SessionRecord{
		{ID: 1, HostAssetID: 1, URL: "http://10.20.0.1/a.php", Status: db.SessionAlive, CreatedByTask: 100},
		{ID: 2, HostAssetID: 2, URL: "http://10.21.0.1/b.php", Status: db.SessionAlive, CreatedByTask: 200},
	}
	topoA := buildTopology(assetsA, filterSessionsByTask(recs, 100), nil, "")
	nodes := topoA["nodes"].([]*topoNode)
	if len(nodes) != 1 || nodes[0].IP != "10.20.0.1" || !nodes[0].HasSession {
		t.Fatalf("task 100 拓扑应只有 10.20.0.1: %+v", nodes)
	}
	topoB := buildTopology(assetsB, filterSessionsByTask(recs, 200), nil, "")
	nodes = topoB["nodes"].([]*topoNode)
	if len(nodes) != 1 || nodes[0].IP != "10.21.0.1" {
		t.Fatalf("task 200 拓扑应只有 10.21.0.1: %+v", nodes)
	}
}

func openIntranetTestDB(t *testing.T) *db.DB {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { pg.Close() })
	return pg
}

func doListItems(t *testing.T, h http.HandlerFunc, url string) []any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s 状态码 = %d, body = %q", url, w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应 JSON 解析失败: %v (%q)", err, w.Body.String())
	}
	items, _ := body["items"].([]any)
	return items
}

func expectBadTaskID(t *testing.T, h http.HandlerFunc, url string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("GET %s 非法 task_id 应 400: %d", url, w.Code)
	}
}

func TestIntranetListSessionsTaskFilter(t *testing.T) {
	pg := openIntranetTestDB(t)
	store := db.NewSessionStore(pg, []byte("intranet-test-master-key"))
	s := &Server{sessStore: store, sessReg: session.NewRegistry()}
	ctx := context.Background()
	mk := func(taskID int64) int64 {
		t.Helper()
		id, err := store.Create(ctx, &db.SessionRecord{
			Kind: "http_php", URL: "http://10.199.0.1/s.php", Lang: "php",
			Status: db.SessionAlive, CreatedByTask: taskID,
		})
		if err != nil {
			t.Fatalf("会话落库失败: %v", err)
		}
		t.Cleanup(func() { _ = store.Delete(context.Background(), id) })
		return id
	}
	id1 := mk(980001)
	mk(980002)

	items := doListItems(t, s.intranetListSessions, "/api/sessions?task_id=980001")
	if len(items) != 1 {
		t.Fatalf("task_id=980001 应只留 1 条: %d", len(items))
	}
	it, _ := items[0].(map[string]any)
	if it["id"].(float64) != float64(id1) || it["created_by_task"].(float64) != 980001 {
		t.Errorf("会话过滤结果错误: %+v", it)
	}
	if all := doListItems(t, s.intranetListSessions, "/api/sessions"); len(all) < 2 {
		t.Fatalf("全局视图应至少 2 条: %d", len(all))
	}
	expectBadTaskID(t, s.intranetListSessions, "/api/sessions?task_id=abc")
}

func TestBuildTopologyAppendsTunnelNodes(t *testing.T) {
	assets := []*db.Asset{{ID: 1, IP: "10.0.0.5", CSegment: "10.0.0.0/24"}}
	recs := []*db.SessionRecord{
		{ID: 11, HostAssetID: 1, URL: "http://10.0.0.5/s.php", Status: db.SessionAlive, CreatedByTask: 3},
	}
	tuns := []topoTunnel{{
		ID: 77, Kind: "socks", ViaSessionID: 11, State: db.TunnelAlive,
	}}
	topo := buildTopology(assets, recs, tuns, "203.0.113.1")
	nodes := topo["nodes"].([]*topoNode)
	byID := map[string]*topoNode{}
	for _, n := range nodes {
		byID[n.ID] = n
	}
	if byID["asset-1"] == nil || !byID["asset-1"].HasSession {
		t.Fatalf("追加隧道后不得丢掉资产/会话节点: %+v", nodes)
	}
	if byID["platform"] == nil {
		t.Fatal("有隧道边时应出现 platform 节点")
	}
	edges := topo["edges"].([]topoEdge)
	if len(edges) != 1 || edges[0].From != "platform" || edges[0].To != "asset-1" || edges[0].Kind != "socks" {
		t.Fatalf("隧道边不符合预期: %+v", edges)
	}
}
