package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAgentSettleSecondsPG(t *testing.T) {
	pg := openTestPG(t)
	key := fmt.Sprintf("settle_test_%d", time.Now().UnixNano())
	a, err := pg.CreateAgent(key, "settlement fixture", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM agents WHERE key=$1`, key) })
	s := &Server{m: &Manager{pg: pg}}
	if a.SettleSecs != 180 || s.agentSettleSeconds(key) != 180 || s.agentSettleSeconds("missing-settlement-fixture") != 180 {
		t.Fatalf("default=%d", a.SettleSecs)
	}
	for _, tc := range []struct {
		body string
		want int
	}{
		{`{"settle_seconds":42}`, 42},
		{`{"run_seconds":600}`, 42},
		{`{"settle_seconds":0}`, 0},
		{`{"settle_seconds":-10}`, 0},
		{`{"settle_seconds":"bad"}`, 0},
	} {
		req := httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(tc.body))
		req.SetPathValue("key", key)
		rec := httptest.NewRecorder()
		s.pgSaveAgentConfig(rec, req)
		wantCode := http.StatusOK
		if strings.Contains(tc.body, "bad") {
			wantCode = http.StatusBadRequest
		}
		if rec.Code != wantCode || s.agentSettleSeconds(key) != tc.want {
			t.Fatalf("body=%s code=%d config=%d response=%s", tc.body, rec.Code, s.agentSettleSeconds(key), rec.Body.String())
		}
	}
}
