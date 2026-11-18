package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestPendingScopeApproveWritesTaskScopeAndDismissStopsAccumulation(t *testing.T) {
	pg := openIntranetTestDB(t)
	task, err := pg.CreateTask("pending-scope fixture", "approve and dismiss", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(task.ID) })
	as := pg.Assets()

	created, err := as.UpsertPendingScope(task.ID, "cidr", "10.9.8.0/24")
	if err != nil || !created {
		t.Fatalf("upsert: created=%v err=%v", created, err)
	}
	// idempotent upsert while pending
	created, err = as.UpsertPendingScope(task.ID, "cidr", "10.9.8.0/24")
	if err != nil || created {
		t.Fatalf("repeat upsert should not create: created=%v err=%v", created, err)
	}

	s := &Server{m: &Manager{pg: pg, assets: as}}
	items, err := as.ListPendingScope(task.ID, false)
	if err != nil || len(items) != 1 {
		t.Fatalf("pending list: %v err=%v", items, err)
	}
	id := items[0].ID

	body, _ := json.Marshal(map[string]string{"action": "approve"})
	req := httptest.NewRequest(http.MethodPost, "/api/pending-scope/"+strconv.FormatInt(id, 10)+"/decide", bytes.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(id, 10))
	w := httptest.NewRecorder()
	s.pendingScopeDecide(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("approve 状态码 = %d body=%s", w.Code, w.Body.String())
	}
	scopes, err := as.ListTaskScope(task.ID)
	if err != nil {
		t.Fatalf("ListTaskScope: %v", err)
	}
	found := false
	for _, sc := range scopes {
		if sc.Kind == "cidr" && sc.Net == "10.9.8.0/24" && sc.Source == "manual" {
			found = true
		}
	}
	if !found {
		t.Fatalf("approve 后 task_scope 应有 kind=cidr source=manual 的 10.9.8.0/24: %+v", scopes)
	}

	// dismiss another segment, then same /24 must not accumulate again
	created, err = as.UpsertPendingScope(task.ID, "cidr", "10.9.9.0/24")
	if err != nil || !created {
		t.Fatalf("upsert dismiss target: created=%v err=%v", created, err)
	}
	items, _ = as.ListPendingScope(task.ID, false)
	var dismissID int64
	for _, it := range items {
		if it.Value == "10.9.9.0/24" {
			dismissID = it.ID
		}
	}
	if dismissID == 0 {
		t.Fatal("missing 10.9.9.0/24 pending row")
	}
	body, _ = json.Marshal(map[string]string{"action": "dismiss"})
	req = httptest.NewRequest(http.MethodPost, "/api/pending-scope/"+strconv.FormatInt(dismissID, 10)+"/decide", bytes.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(dismissID, 10))
	w = httptest.NewRecorder()
	s.pendingScopeDecide(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("dismiss 状态码 = %d body=%s", w.Code, w.Body.String())
	}
	got, err := as.GetPendingScope(dismissID)
	if err != nil || got.Status != "dismissed" {
		t.Fatalf("dismiss 后状态应为 dismissed: %+v err=%v", got, err)
	}
	hits := got.Hits
	created, err = as.UpsertPendingScope(task.ID, "cidr", "10.9.9.0/24")
	if err != nil || created {
		t.Fatalf("dismiss 后再 upsert 不得新建: created=%v err=%v", created, err)
	}
	again, err := as.GetPendingScope(dismissID)
	if err != nil {
		t.Fatalf("get after upsert: %v", err)
	}
	if again.Hits != hits || again.Status != "dismissed" {
		t.Fatalf("dismiss 后同一网段不得再累计: %+v (was hits=%d)", again, hits)
	}
}

func TestScopeRulesFromRows(t *testing.T) {
	rows := []db.TaskScope{
		{Kind: "cidr", Net: "10.0.0.0/24"},
		{Kind: "root_domain", Domain: "example.com"},
		{Kind: "keyword", Value: "ignored"},
	}
	rules := scopeRulesFromRows(rows)
	if len(rules) != 2 {
		t.Fatalf("keyword 不应进入匹配规则: %+v", rules)
	}
}
