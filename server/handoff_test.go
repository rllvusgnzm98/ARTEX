package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/session"
)

func TestHandoffHostIPAndGoal(t *testing.T) {
	rec := &db.SessionRecord{ID: 7, Kind: "http_php", URL: "http://10.55.66.77/fixture.php"}
	s := &Server{}
	if ip := s.handoffHostIP(rec); ip != "10.55.66.77" {
		t.Fatalf("URL 字面量 IP: got %q", ip)
	}
	if ip := s.handoffHostIP(&db.SessionRecord{URL: "http://intranet.example.invalid/"}); ip != "" {
		t.Fatalf("非 IP host 应得空: %q", ip)
	}

	pending := []db.PendingScope{{Value: "10.10.10.0/24"}}
	scope := []db.TaskScope{{Kind: "cidr", Net: "192.168.1.0/24"}}
	goal := handoffGoal(rec, "10.55.66.77", pending, scope)
	if !strings.Contains(goal, "10.55.66.77/32") {
		t.Fatalf("goal 应声明初始 /32: %s", goal)
	}
	if !strings.Contains(goal, "10.10.10.0/24") {
		t.Fatalf("goal 应列出 pending 网段: %s", goal)
	}
	if !strings.Contains(goal, "扩容队列") || !strings.Contains(goal, "不是出界行动硬闸") {
		t.Fatalf("goal 应写明 pending_scope 不是硬闸: %s", goal)
	}
	if strings.Contains(goal, "批准前不得") || strings.Contains(goal, "严禁直接动") {
		t.Fatalf("goal 不得把 pending 写成硬闸: %s", goal)
	}
	if footholdSegment("10.55.66.77") != "10.55.66.0/24" {
		t.Fatalf("立足点 /24 推导错误: %s", footholdSegment("10.55.66.77"))
	}
}

func TestSessionHandoffScopeAndPending(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { m.Close() })

	parent, err := m.CreateTaskWithOptions("handoff parent", "parent fixture", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	parentID := mustTaskID(t, parent.ID)
	if _, err := m.Assets().UpsertPendingScope(parentID, "cidr", "10.10.10.0/24"); err != nil {
		t.Fatalf("parent pending: %v", err)
	}

	ss := db.NewSessionStore(m.PG(), []byte("intranet-test-master-key"))
	sessID, err := ss.Create(context.Background(), &db.SessionRecord{
		Kind: "http_php", URL: "http://10.55.66.77/fixture.php", Lang: "php",
		Status: db.SessionAlive, CreatedByTask: parentID,
	})
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	t.Cleanup(func() { _ = ss.Delete(context.Background(), sessID) })

	s := &Server{m: m, sessStore: ss, sessReg: session.NewRegistry()}
	req := httptest.NewRequest(http.MethodPost, "/api/sessions/"+itoa(sessID)+"/handoff", nil)
	req.SetPathValue("id", itoa(sessID))
	w := httptest.NewRecorder()
	s.sessionHandoff(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("handoff 状态码=%d body=%s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	childIDStr, _ := body["task_id"].(string)
	if childIDStr == "" {
		t.Fatalf("应返回 task_id: %s", w.Body.String())
	}
	childID := mustTaskID(t, childIDStr)

	scopes, err := m.Assets().ListTaskScope(childID)
	if err != nil {
		t.Fatal(err)
	}
	gotNet := []string{}
	for _, sc := range scopes {
		gotNet = append(gotNet, sc.Kind+"="+sc.Net)
		if sc.Net == "10.10.10.0/24" {
			t.Fatalf("新网段不得直接进入官方 task_scope: %+v", scopes)
		}
	}
	found32 := false
	for _, sc := range scopes {
		if sc.Net == "10.55.66.77/32" {
			found32 = true
			if sc.Source != "manual" {
				t.Fatalf("立足点 scope source 应为 manual: %+v", sc)
			}
		}
	}
	if !found32 {
		t.Fatalf("子任务官方 scope 应含立足点 /32, got %v", gotNet)
	}

	pending, err := m.Assets().ListPendingScope(childID, false)
	if err != nil {
		t.Fatal(err)
	}
	gotPending := map[string]bool{}
	for _, p := range pending {
		gotPending[p.Value] = true
	}
	if !gotPending["10.10.10.0/24"] {
		t.Fatalf("来源任务的新网段应进入子任务 pending_scope: %+v", pending)
	}
	if !gotPending["10.55.66.0/24"] {
		t.Fatalf("立足点所在 /24 应进入 pending_scope 扩容队列: %+v", pending)
	}
}

func TestSessionHandoffRejectsUnknownHost(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { m.Close() })
	parent, err := m.CreateTaskWithOptions("handoff parent noip", "fixture", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ss := db.NewSessionStore(m.PG(), []byte("intranet-test-master-key"))
	sessID, err := ss.Create(context.Background(), &db.SessionRecord{
		Kind: "http_php", URL: "http://intranet.example.invalid/fixture.php",
		Status: db.SessionAlive, CreatedByTask: mustTaskID(t, parent.ID),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Delete(context.Background(), sessID) })
	s := &Server{m: m, sessStore: ss, sessReg: session.NewRegistry()}
	req := httptest.NewRequest(http.MethodPost, "/api/sessions/"+itoa(sessID)+"/handoff", nil)
	req.SetPathValue("id", itoa(sessID))
	w := httptest.NewRecorder()
	s.sessionHandoff(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("无法解析立足点 IP 应 400: %d %s", w.Code, w.Body.String())
	}
}

func itoa(id int64) string {
	return jsonInt(id)
}

func jsonInt(id int64) string {
	b, _ := json.Marshal(id)
	return string(b)
}
