package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

const interceptCredFixturePass = "fixture-pass"

func TestInterceptPendingAndHistoryRedactCredentialSecret(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	m := &Manager{pg: d, interceptor: intercept.New(d)}
	s := &Server{m: m, jwtKey: []byte("cred-redact-http-test-key")}
	h := s.Handler()
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}

	raw := []byte(`{"cred_type":"password","secret":"fixture-pass","source":"fixture source","username":"fixture-admin"}`)
	scope := "cred-redact-http"
	pendingID, err := d.CreateInterceptPending(0, 0, scope, "worker", "add_credential", raw, "fixture ask")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM intercept_pending WHERE id=$1`, pendingID) })
	histID, err := d.CreateDecidedIntercept(0, 0, scope, "worker", "add_credential", raw, "denied", "fixture history")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM intercept_pending WHERE id=$1`, histID) })

	do := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s 状态码=%d body=%s", path, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), interceptCredFixturePass) {
			t.Fatalf("GET %s 不得含明文 secret: %s", path, rec.Body.String())
		}
		return rec
	}

	pendingBody := do("/api/intercept/pending")
	var pendingWrap struct {
		Pending []db.InterceptPending `json:"pending"`
	}
	if err := json.Unmarshal(pendingBody.Body.Bytes(), &pendingWrap); err != nil {
		t.Fatal(err)
	}
	foundPending := false
	for _, p := range pendingWrap.Pending {
		if p.ID == pendingID {
			foundPending = true
			if strings.Contains(string(p.ToolInput), interceptCredFixturePass) {
				t.Fatalf("pending.tool_input 仍含明文: %s", p.ToolInput)
			}
		}
	}
	if !foundPending {
		t.Fatalf("GET /api/intercept/pending 应包含刚写入的行 #%d", pendingID)
	}

	one := do(fmt.Sprintf("/api/intercept/pending/%d", pendingID))
	if strings.Contains(one.Body.String(), interceptCredFixturePass) {
		t.Fatalf("GET pending one 含明文: %s", one.Body.String())
	}

	histBody := do("/api/intercept/history")
	var histWrap struct {
		Items []db.InterceptApprovalRow `json:"items"`
	}
	if err := json.Unmarshal(histBody.Body.Bytes(), &histWrap); err != nil {
		t.Fatal(err)
	}
	foundHist := false
	for _, it := range histWrap.Items {
		if it.ID == histID {
			foundHist = true
			if strings.Contains(string(it.ToolInput), interceptCredFixturePass) {
				t.Fatalf("history tool_input 仍含明文: %s", it.ToolInput)
			}
		}
	}
	if !foundHist {
		t.Fatalf("GET /api/intercept/history 应包含已决行 #%d", histID)
	}
}
