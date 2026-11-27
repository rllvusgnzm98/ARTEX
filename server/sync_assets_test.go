package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/notify"
)

func TestFofaSyncAndCollectionRoE(t *testing.T) {
	pg := openTestPG(t)
	withRoEMode(t, pg, "strict")

	// Backup & restore FOFA settings.
	prevEmail, hadEmail, _ := pg.GetSetting(settingFofaEmail)
	prevKey, hadKey, _ := pg.GetSetting(settingFofaKey)
	t.Cleanup(func() {
		if hadEmail {
			_ = pg.SetSetting(settingFofaEmail, prevEmail)
		} else {
			_, _ = pg.Exec(`DELETE FROM settings WHERE key=$1`, settingFofaEmail)
		}
		if hadKey {
			_ = pg.SetSetting(settingFofaKey, prevKey)
		} else {
			_, _ = pg.Exec(`DELETE FROM settings WHERE key=$1`, settingFofaKey)
		}
		_, _ = pg.Exec(`DELETE FROM assets WHERE domain LIKE '%fofa-unit.example' OR root_domain = 'fofa-unit.example' OR ip IN ('198.51.100.21','198.51.100.22')`)
	})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != "fofa-test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v1/info/my":
			_ = json.NewEncoder(w).Encode(map[string]any{"error": false})
		case "/api/v1/search/all":
			qBytes, _ := base64.StdEncoding.DecodeString(r.URL.Query().Get("qbase64"))
			if string(qBytes) != `domain="fofa-unit.example"` {
				_ = json.NewEncoder(w).Encode(map[string]any{"error": true, "errmsg": "unexpected query"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": false,
				"mode":  "extended",
				"size":  2,
				"results": [][]string{
					{"https://portal.fofa-unit.example:8443", "198.51.100.21", "8443", "https", "fofa-unit.example", "Portal Login", "nginx/1.24", "京ICP备20260001号"},
					{"198.51.100.22:22", "198.51.100.22", "22", "ssh", "", "", "OpenSSH", ""},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	origBase := fofaAPIBase
	fofaAPIBase = ts.URL
	t.Cleanup(func() { fofaAPIBase = origBase })

	s := &Server{m: &Manager{pg: pg, assets: pg.Assets()}}

	// Save datasource & verify masked update preserves real key.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/sync/fofa/datasource", bytes.NewBufferString(`{"email":"ops@example.com","key":"fofa-test-key"}`))
	s.syncFofaDatasource(rec, req)
	if rec.Code != 200 {
		t.Fatalf("syncFofaDatasource status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/sync/fofa/datasource", bytes.NewBufferString(`{"email":"","key":"`+notify.MaskedValue("fofa-test-key")+`"}`))
	s.syncFofaDatasource(rec, req)
	if _, gotKey := s.fofaCreds(); gotKey != "fofa-test-key" {
		t.Fatalf("masked save overwrote key: got %q", gotKey)
	}

	// Probe status.
	rec = httptest.NewRecorder()
	s.syncFofaStatus(rec, httptest.NewRequest(http.MethodGet, "/api/sync/fofa/status", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"reachable":true`) {
		t.Fatalf("syncFofaStatus unexpected: code=%d body=%s", rec.Code, rec.Body.String())
	}

	// Sync into named collection.
	colName := "FOFA-Unit-Collection"
	rec = httptest.NewRecorder()
	s.syncFofaRun(rec, httptest.NewRequest(http.MethodPost, "/api/sync/fofa/sync",
		bytes.NewBufferString(`{"query":"domain=\"fofa-unit.example\"","size":10,"collection_name":"`+colName+`"}`)))
	if rec.Code != 200 {
		t.Fatalf("syncFofaRun code=%d body=%s", rec.Code, rec.Body.String())
	}
	var syncResp struct {
		Imported   int            `json:"imported"`
		Synced     map[string]int `json:"synced"`
		Collection struct {
			ID      int64  `json:"id"`
			Name    string `json:"name"`
			Members int    `json:"members"`
		} `json:"collection"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &syncResp); err != nil {
		t.Fatalf("decode syncResp: %v", err)
	}
	if syncResp.Imported != 2 || syncResp.Collection.ID <= 0 || syncResp.Collection.Members < 2 {
		t.Fatalf("unexpected syncResp: %+v", syncResp)
	}
	t.Cleanup(func() { _ = pg.DeleteCollection(syncResp.Collection.ID) })

	// Create task referencing this collection and verify RoE strict enforcement!
	task, err := pg.CreateTaskWithOptions("fofa col roe test", "verify collection scope", db.TaskCreateOptions{
		CollectionIDs: []int64{syncResp.Collection.ID},
	})
	if err != nil {
		t.Fatalf("CreateTaskWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(task.ID) })

	scopes, err := pg.Assets().ListTaskScope(task.ID)
	if err != nil || len(scopes) != 1 || scopes[0].Kind != "collection" || scopes[0].CollectionName != colName {
		t.Fatalf("unexpected task scopes: err=%v scopes=%+v", err, scopes)
	}

	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: task.ID})
	// Member host & member IP must be allowed under strict RoE.
	for _, inHost := range []string{"portal.fofa-unit.example", "198.51.100.21", "198.51.100.22"} {
		if _, err := s.roeCheckHost(ctx, inHost, "目标"); err != nil {
			t.Fatalf("collection member %s should be allowed in strict RoE: %v", inHost, err)
		}
	}
	// Non-member host must be denied under strict RoE.
	if _, err := s.roeCheckHost(ctx, "evil-outside.invalid", "目标"); err == nil {
		t.Fatalf("out-of-collection host should be blocked under strict RoE")
	}
	// Explicit exclude_subdomain overrides collection membership.
	if _, err := pg.Assets().AddAgentScope(task.ID, "exclude_subdomain", "portal.fofa-unit.example", "exclude test", "manual"); err != nil {
		t.Fatalf("AddAgentScope exclude: %v", err)
	}
	if _, err := s.roeCheckHost(ctx, "portal.fofa-unit.example", "目标"); err == nil {
		t.Fatalf("excluded host should be blocked even when in collection")
	}
}

func TestShodanSyncSearchAndDirectIP(t *testing.T) {
	pg := openTestPG(t)

	prevKey, hadKey, _ := pg.GetSetting(settingShodanKey)
	t.Cleanup(func() {
		if hadKey {
			_ = pg.SetSetting(settingShodanKey, prevKey)
		} else {
			_, _ = pg.Exec(`DELETE FROM settings WHERE key=$1`, settingShodanKey)
		}
		_, _ = pg.Exec(`DELETE FROM assets WHERE domain LIKE '%shodan-unit.example' OR root_domain = 'shodan-unit.example' OR ip IN ('203.0.113.10','203.0.113.11','203.0.113.55')`)
	})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != "shodan-test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "Invalid API key"})
			return
		}
		switch r.URL.Path {
		case "/api-info":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"plan":          "dev",
				"query_credits": 95,
				"scan_credits":  100,
			})
		case "/shodan/host/search":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"total": 2,
				"matches": []map[string]any{
					{
						"ip_str":    "203.0.113.10",
						"port":      443,
						"transport": "tcp",
						"hostnames": []string{"sso.shodan-unit.example"},
						"domains":   []string{"shodan-unit.example"},
						"org":       "Acme Corp",
						"product":   "nginx",
						"version":   "1.25.3",
						"ssl":       map[string]any{"cipher": map[string]any{"name": "TLS_AES_256"}},
						"_shodan":   map[string]any{"module": "https-simple-new"},
						"http": map[string]any{
							"host":   "sso.shodan-unit.example",
							"title":  "Acme SSO",
							"server": "nginx/1.25.3",
							"status": 200,
							"favicon": map[string]any{
								"hash": -123456789,
							},
							"components": map[string]any{
								"React": map[string]any{},
							},
						},
					},
					{
						"ip_str":    "203.0.113.11",
						"port":      3389,
						"transport": "tcp",
						"hostnames": []string{"rdp.shodan-unit.example"},
						"domains":   []string{"shodan-unit.example"},
						"org":       "Acme Corp",
						"product":   "Microsoft Terminal Services",
						"_shodan":   map[string]any{"module": "rdp"},
					},
				},
			})
		case "/shodan/host/203.0.113.55":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ip_str":    "203.0.113.55",
				"org":       "Acme Lab",
				"hostnames": []string{"vpn.shodan-unit.example"},
				"domains":   []string{"shodan-unit.example"},
				"data": []map[string]any{
					{
						"port":      80,
						"transport": "tcp",
						"_shodan":   map[string]any{"module": "http"},
						"http":      map[string]any{"title": "VPN Portal", "status": 200},
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	origBase, origDelay := shodanAPIBase, shodanPageDelay
	shodanAPIBase = ts.URL
	shodanPageDelay = 0
	t.Cleanup(func() {
		shodanAPIBase = origBase
		shodanPageDelay = origDelay
	})

	s := &Server{m: &Manager{pg: pg, assets: pg.Assets()}}

	// Configure key.
	rec := httptest.NewRecorder()
	s.syncShodanDatasource(rec, httptest.NewRequest(http.MethodPost, "/api/sync/shodan/datasource", bytes.NewBufferString(`{"key":"shodan-test-key"}`)))
	if rec.Code != 200 {
		t.Fatalf("syncShodanDatasource code=%d body=%s", rec.Code, rec.Body.String())
	}

	// Probe status.
	rec = httptest.NewRecorder()
	s.syncShodanStatus(rec, httptest.NewRequest(http.MethodGet, "/api/sync/shodan/status", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"plan":"dev"`) || !strings.Contains(rec.Body.String(), `"query_credits":95`) {
		t.Fatalf("syncShodanStatus unexpected: code=%d body=%s", rec.Code, rec.Body.String())
	}

	// Preview direct IP lookup (mode=host).
	rec = httptest.NewRecorder()
	s.syncShodanQuery(rec, httptest.NewRequest(http.MethodPost, "/api/sync/shodan/query", bytes.NewBufferString(`{"query":"203.0.113.55","size":10}`)))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"mode":"host"`) || !strings.Contains(rec.Body.String(), `"VPN Portal"`) {
		t.Fatalf("syncShodanQuery direct IP unexpected: code=%d body=%s", rec.Code, rec.Body.String())
	}

	// Sync search query into collection.
	rec = httptest.NewRecorder()
	s.syncShodanRun(rec, httptest.NewRequest(http.MethodPost, "/api/sync/shodan/sync",
		bytes.NewBufferString(`{"query":"hostname:shodan-unit.example","size":10,"collection_name":"Shodan-Unit-Collection"}`)))
	if rec.Code != 200 {
		t.Fatalf("syncShodanRun code=%d body=%s", rec.Code, rec.Body.String())
	}
	var syncResp struct {
		Imported   int            `json:"imported"`
		Synced     map[string]int `json:"synced"`
		Collection struct {
			ID      int64  `json:"id"`
			Name    string `json:"name"`
			Members int    `json:"members"`
		} `json:"collection"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &syncResp); err != nil {
		t.Fatalf("decode syncResp: %v", err)
	}
	if syncResp.Imported != 2 || syncResp.Synced["service"] != 2 || syncResp.Synced["ip"] != 2 || syncResp.Collection.ID <= 0 {
		t.Fatalf("unexpected shodan syncResp: %+v", syncResp)
	}
	t.Cleanup(func() { _ = pg.DeleteCollection(syncResp.Collection.ID) })

	// List & delete collection API.
	rec = httptest.NewRecorder()
	s.listCollections(rec, httptest.NewRequest(http.MethodGet, "/api/collections", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"source":"shodan"`) {
		t.Fatalf("listCollections unexpected: code=%d body=%s", rec.Code, rec.Body.String())
	}

	reqDel := httptest.NewRequest(http.MethodDelete, "/api/collections/"+strconv.FormatInt(syncResp.Collection.ID, 10), nil)
	reqDel.SetPathValue("id", strconv.FormatInt(syncResp.Collection.ID, 10))
	rec = httptest.NewRecorder()
	s.deleteCollection(rec, reqDel)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"deleted":true`) {
		t.Fatalf("deleteCollection unexpected: code=%d body=%s", rec.Code, rec.Body.String())
	}
}
