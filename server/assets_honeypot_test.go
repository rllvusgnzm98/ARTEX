package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postInsertAssets(t *testing.T, s *Server, body any) (ids []int64, raw []byte) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/assets", bytes.NewReader(b))
	w := httptest.NewRecorder()
	s.insertAssets(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/assets status=%d body=%s", w.Code, w.Body.String())
	}
	raw = w.Body.Bytes()
	var out struct {
		Results []struct {
			ID int64 `json:"id"`
		} `json:"results"`
		Errors []any `json:"errors"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, raw)
	}
	if len(out.Errors) > 0 {
		t.Fatalf("unexpected errors: %s", raw)
	}
	for _, r := range out.Results {
		ids = append(ids, r.ID)
	}
	if len(ids) == 0 {
		t.Fatalf("no ids: %s", raw)
	}
	return ids, raw
}

func TestAPIInsertAssetsRunsHoneypotEvaluation(t *testing.T) {
	pg := openIntranetTestDB(t)
	s := &Server{m: &Manager{pg: pg}}

	const httpURL = "http://203.0.113.90:8080/"
	const tlsIP = "203.0.113.91"
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM assets WHERE url=$1 OR ip=$2`, httpURL, tlsIP)
	})

	ids, _ := postInsertAssets(t, s, map[string]any{
		"assets": []any{map[string]any{
			"type": "service",
			"url":  httpURL,
			"body": "fixture login includes /x.js",
		}},
	})
	var score float64
	var ev string
	if err := pg.QueryRow(`SELECT honeypot_score, COALESCE(honeypot_evidence,'') FROM assets WHERE id=$1`, ids[0]).Scan(&score, &ev); err != nil {
		t.Fatal(err)
	}
	if score < 0.84 || !strings.Contains(ev, "hfish_default_web_xjs") {
		t.Fatalf("API 登记 HTTP service 后应写 body 命中分数: score=%v ev=%s", score, ev)
	}

	ids, _ = postInsertAssets(t, s, map[string]any{
		"assets": []any{map[string]any{
			"type":         "service",
			"service_name": "tls",
			"ip":           tlsIP,
			"port":         443,
			"cert_issuer":  "O=dionaea.carnivore.it, CN=Nepenthes Development Team",
		}},
	})
	if err := pg.QueryRow(`SELECT honeypot_score, COALESCE(honeypot_evidence,'') FROM assets WHERE id=$1`, ids[0]).Scan(&score, &ev); err != nil {
		t.Fatal(err)
	}
	if score < 0.89 || !strings.Contains(ev, "dionaea_default_cert_issuer") {
		t.Fatalf("API 登记非 HTTP service 后应写证书命中分数: score=%v ev=%s", score, ev)
	}

	// 无观测字段：不要求写分数
	plainURL := "http://203.0.113.92/"
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM assets WHERE url=$1`, plainURL) })
	ids, _ = postInsertAssets(t, s, map[string]any{
		"assets": []any{map[string]any{"type": "service", "url": plainURL, "page_title": "ok"}},
	})
	if err := pg.QueryRow(`SELECT honeypot_score, COALESCE(honeypot_evidence,'') FROM assets WHERE id=$1`, ids[0]).Scan(&score, &ev); err != nil {
		t.Fatal(err)
	}
	if score != 0 || ev != "" && ev != "[]" && ev != "null" {
		if strings.Contains(ev, "glastopf") || strings.Contains(ev, "hfish") || strings.Contains(ev, "dionaea") {
			t.Fatalf("无 body/证书时不应命中这些签名: score=%v ev=%s", score, ev)
		}
	}

}
