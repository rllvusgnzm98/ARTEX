package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/session"
	actool "github.com/Autumn-27/norma/tool"
)

func TestRegisterSessionHTTPMethodPassthrough(t *testing.T) {
	pg := openIntranetTestDB(t)
	task, err := pg.CreateTask("register session method test", "verify GET and POST", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM sessions WHERE created_by_task=$1`, task.ID)
		_ = pg.DeleteTask(task.ID)
	})

	var lastMethod atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastMethod.Store(r.Method)
		var cmdVal string
		if r.Method == http.MethodGet {
			cmdVal = r.URL.Query().Get("cmd")
		} else {
			_ = r.ParseForm()
			cmdVal = r.Form.Get("cmd")
		}
		cmdVal = strings.TrimPrefix(cmdVal, "echo ")
		cmdVal = strings.TrimSuffix(strings.TrimSpace(cmdVal), "2>&1")
		cmdVal = strings.TrimSpace(cmdVal)
		cmdVal = strings.ReplaceAll(cmdVal, "$((40+2))", "42")
		_, _ = w.Write([]byte(cmdVal))
	}))
	t.Cleanup(srv.Close)

	store := db.NewSessionStore(pg, []byte("register-method-test-master-key!"))
	s := &Server{
		m:         &Manager{pg: pg, assets: pg.Assets()},
		sessStore: store,
		sessReg:   session.NewRegistry(),
		ctx:       context.Background(),
	}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: task.ID})
	tool := s.registerSessionTool()

	for _, tc := range []struct {
		name       string
		methodArg  string
		wantMethod string
	}{
		{name: "GET passthrough", methodArg: "GET", wantMethod: "GET"},
		{name: "POST passthrough", methodArg: "POST", wantMethod: "POST"},
		{name: "default POST", methodArg: "", wantMethod: "POST"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inMap := map[string]any{
				"url":      srv.URL + "/shell.php",
				"password": "cmd",
				"lang":     "phpcmd",
			}
			if tc.methodArg != "" {
				inMap["method"] = tc.methodArg
			}
			in, _ := json.Marshal(inMap)
			res, err := tool.Call(ctx, in, &actool.ToolContext{})
			if err != nil {
				t.Fatalf("Call: %v", err)
			}
			if res.IsError {
				t.Fatalf("unexpected tool error: %s", res.Flatten())
			}
			out := toolResultJSON(t, res)
			if got, _ := out["method"].(string); got != tc.wantMethod {
				t.Fatalf("out[method]=%q, want %q", got, tc.wantMethod)
			}
			if got, _ := lastMethod.Load().(string); got != tc.wantMethod {
				t.Fatalf("HTTP server received method %q, want %q", got, tc.wantMethod)
			}
			sessID := int64(out["session_id"].(float64))
			t.Cleanup(func() {
				s.sessReg.Remove(sessID)
				_ = store.Delete(context.Background(), sessID)
			})

			sess, ok := s.sessReg.Get(sessID)
			if !ok {
				t.Fatalf("session %d not in registry", sessID)
			}
			hs, ok := sess.(*session.HTTPShell)
			if !ok {
				t.Fatalf("expected *session.HTTPShell, got %T", sess)
			}
			if hs.Method() != tc.wantMethod {
				t.Fatalf("HTTPShell.Method()=%q, want %q", hs.Method(), tc.wantMethod)
			}
			hs.SetMethod("GET")
			if hs.Method() != "GET" {
				t.Fatalf("after SetMethod(GET), Method()=%q", hs.Method())
			}

			rec, gerr := store.Get(context.Background(), sessID)
			if gerr != nil || rec == nil {
				t.Fatalf("store.Get(%d): %v", sessID, gerr)
			}
			var sec map[string]any
			if jerr := json.Unmarshal(rec.Secret, &sec); jerr != nil {
				t.Fatalf("unmarshal secret: %v", jerr)
			}
			if m, _ := sec["method"].(string); !strings.EqualFold(m, tc.wantMethod) {
				t.Fatalf("persisted Secret.method=%q, want %q", m, tc.wantMethod)
			}
		})
	}

	// Reject invalid HTTP method without probing.
	badIn, _ := json.Marshal(map[string]any{"url": srv.URL + "/shell.php", "method": "PUT"})
	badRes, err := tool.Call(ctx, badIn, &actool.ToolContext{})
	if err != nil {
		t.Fatalf("Call bad method: %v", err)
	}
	if !badRes.IsError || !strings.Contains(badRes.Flatten(), "GET") {
		t.Fatalf("expected invalid method error, got: %s", badRes.Flatten())
	}
}

func TestRegisterSessionLogicalKindsSkipProbeAndStartupDeadMark(t *testing.T) {
	pg := openIntranetTestDB(t)
	task, err := pg.CreateTask("register logical session test", "winrm ssh msf_bind", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM sessions WHERE created_by_task=$1`, task.ID)
		_ = pg.DeleteTask(task.ID)
	})

	var httpHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpHits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	store := db.NewSessionStore(pg, []byte("logical-session-test-master-key"))
	s := &Server{
		m:         &Manager{pg: pg, assets: pg.Assets()},
		sessStore: store,
		sessReg:   session.NewRegistry(),
		ctx:       context.Background(),
	}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: task.ID})
	tool := s.registerSessionTool()

	cases := []struct {
		name     string
		input    map[string]any
		wantKind string
		wantURL  string
		wantHost string
		wantPort int
	}{
		{
			name: "winrm via host+port",
			input: map[string]any{
				"kind":     "winrm",
				"host":     "10.10.10.20",
				"port":     5985,
				"username": "administrator",
				"password": "fixture-winrm-password",
				"method":   "ntlm",
				"notes":    "evil-winrm via socks5",
			},
			wantKind: "winrm",
			wantURL:  "winrm://10.10.10.20:5985",
			wantHost: "10.10.10.20",
			wantPort: 5985,
		},
		{
			name: "ssh via url",
			input: map[string]any{
				"kind":     "ssh",
				"url":      "ssh://10.10.10.30:2222",
				"username": "ops",
				"method":   "key",
				"notes":    "id_ed25519 in shared/",
			},
			wantKind: "ssh",
			wantURL:  "ssh://10.10.10.30:2222",
			wantHost: "10.10.10.30",
			wantPort: 2222,
		},
		{
			name: "msf_bind via host+port",
			input: map[string]any{
				"kind":   "msf_bind",
				"host":   "10.10.10.40",
				"port":   4444,
				"method": "bind_tcp",
				"notes":  "meterpreter bind shell",
			},
			wantKind: "msf_bind",
			wantURL:  "msf_bind://10.10.10.40:4444",
			wantHost: "10.10.10.40",
			wantPort: 4444,
		},
	}

	var recs []*db.SessionRecord
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in, _ := json.Marshal(tc.input)
			res, err := tool.Call(ctx, in, &actool.ToolContext{})
			if err != nil {
				t.Fatalf("Call: %v", err)
			}
			if res.IsError {
				t.Fatalf("unexpected error: %s", res.Flatten())
			}
			out := toolResultJSON(t, res)
			if got, _ := out["kind"].(string); got != tc.wantKind {
				t.Fatalf("kind=%q, want %q", got, tc.wantKind)
			}
			if got, _ := out["url"].(string); got != tc.wantURL {
				t.Fatalf("url=%q, want %q", got, tc.wantURL)
			}
			if logical, _ := out["logical"].(bool); !logical {
				t.Fatalf("expected logical=true, got %v", out)
			}
			id := int64(out["session_id"].(float64))

			rec, gerr := store.Get(context.Background(), id)
			if gerr != nil || rec == nil {
				t.Fatalf("Get(%d): %v", id, gerr)
			}
			if rec.Kind != tc.wantKind || rec.URL != tc.wantURL || rec.Status != db.SessionAlive {
				t.Fatalf("unexpected record: %+v", rec)
			}
			if rec.HostAssetID <= 0 {
				t.Fatalf("expected host_asset_id > 0 for IP host, got %d", rec.HostAssetID)
			}
			item := sessionItem(rec)
			if item["host"] != tc.wantHost || item["port"] != tc.wantPort {
				t.Fatalf("sessionItem host/port mismatch: %+v", item)
			}
			if _, hasPass := item["password"]; hasPass {
				t.Fatalf("sessionItem must not expose password: %+v", item)
			}
			// Mark last_beat stale (>24h) and verify startupProbeStaleAt leaves it alive.
			if _, uerr := pg.Exec(`UPDATE sessions SET last_beat=$2 WHERE id=$1`, id, time.Now().Add(-48*time.Hour)); uerr != nil {
				t.Fatalf("backdate last_beat: %v", uerr)
			}
			rec, _ = store.Get(context.Background(), id)
			if sessionNeedsStartupProbe(rec, time.Now(), sessionStaleProbeAge) {
				t.Fatalf("logical kind %s must never require startup probe", rec.Kind)
			}
			recs = append(recs, rec)
		})
	}
	t.Cleanup(func() {
		for _, r := range recs {
			_ = store.Delete(context.Background(), r.ID)
		}
	})

	if httpHits.Load() != 0 {
		t.Fatalf("logical session registration must not issue HTTP probes, got %d hits", httpHits.Load())
	}

	// Verify startupProbeStaleAt never marks logical records dead even if last_beat is stale.
	s.startupProbeStaleAt(recs, time.Now())
	for _, r := range recs {
		fresh, gerr := store.Get(context.Background(), r.ID)
		if gerr != nil || fresh == nil || fresh.Status != db.SessionAlive {
			t.Fatalf("logical session %d (%s) should stay alive after startupProbeStaleAt: %+v err=%v", r.ID, r.Kind, fresh, gerr)
		}
	}
}
