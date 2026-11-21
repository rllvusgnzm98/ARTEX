package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Autumn-27/artex/agent/dualverify"
)

func dualVerifyTestPlan(t *testing.T, target string, write, session, tenant bool) dualverify.Plan {
	t.Helper()
	request := func(method, body string) dualverify.Request {
		return dualverify.Request{Method: method, URL: target + "/private/{{RESOURCE_ID}}", Headers: map[string]string{"Authorization": "Bearer {{AUTH}}"}, Body: body}
	}
	p, err := dualverify.BuildPlan(dualverify.Spec{Target: request("GET", ""), Plant: request("PATCH", `{"plant":"{{MARKER}}"}`), Cleanup: request("DELETE", `{"remove":"{{MARKER}}"}`), ResourceID: "a-resource", Marker: "artex-mark-local-private", Read: true, Write: write, SessionToken: session, TenantRole: tenant, AllowWrite: write})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func dualVerifyTestSecrets() map[string]string {
	return map[string]string{"A": "test-owner-credential-934824", "B": "test-other-credential-298754", "B_expired": "test-expired-credential-283745"}
}

func dualVerifyObservation(t *testing.T, observations []dualverify.Observation, id string) dualverify.Observation {
	t.Helper()
	for _, o := range observations {
		if o.StepID == id {
			return o
		}
	}
	t.Fatalf("missing %s", id)
	return dualverify.Observation{}
}

func TestDualVerifyProvidedMarker(t *testing.T) {
	for _, leak := range []bool{false, true} {
		t.Run(map[bool]string{false: "owner only", true: "B reads owner marker"}[leak], func(t *testing.T) {
			marker, err := dualVerifyMarker(dualVerifyInput{Marker: "  preplanted-unique-marker  "})
			if err != nil {
				t.Fatal(err)
			}
			secrets := dualVerifyTestSecrets()
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				if auth == "Bearer "+secrets["A"] || (leak && auth == "Bearer "+secrets["B"]) {
					io.WriteString(w, marker)
					return
				}
				w.WriteHeader(403)
			}))
			defer backend.Close()
			p := dualVerifyTestPlan(t, backend.URL, false, false, false)
			p.Marker = marker
			o, err := runDualVerify(context.Background(), backend.Client(), p, secrets, func(string) (dualverify.Scope, bool) { return dualverify.ScopeIn, false }, true)
			if err != nil {
				t.Fatal(err)
			}
			r, err := dualverify.Evaluate(p, o)
			if err != nil {
				t.Fatal(err)
			}
			want := dualverify.ControlsHold
			if leak {
				want = dualverify.Verified
			}
			if r.Verdict != want {
				t.Fatal(r)
			}
		})
	}
	for _, a := range []dualVerifyInput{{}, {Write: true}, {AllowWrite: true}} {
		if _, err := dualVerifyMarker(a); err == nil || !strings.Contains(err.Error(), "write + allow_write") {
			t.Fatalf("missing operator guidance: %v", err)
		}
	}
	var s Server
	res, err := s.executeDualVerify(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(res)
	if !strings.Contains(string(raw), "write + allow_write") {
		t.Fatalf("missing tool error: %s", raw)
	}
	for _, marker := range []string{"short", "marker{{bad}}", "marker\nbad", "marker\rbad", strings.Repeat("x", 257), strings.Repeat("界", 86)} {
		if _, err := dualVerifyMarker(dualVerifyInput{Marker: marker}); err == nil {
			t.Errorf("accepted invalid marker %q", marker)
		}
	}
	for _, marker := range []string{strings.Repeat("界", 8), strings.Repeat("x", 256)} {
		if got, err := dualVerifyMarker(dualVerifyInput{Marker: marker}); err != nil || got != marker {
			t.Fatalf("valid marker rejected: %v", err)
		}
	}
	if marker, err := dualVerifyMarker(dualVerifyInput{Write: true, AllowWrite: true}); err != nil || !strings.HasPrefix(marker, "artex-mark-") {
		t.Fatalf("automatic marker: %q %v", marker, err)
	}
}

func TestDualVerifyReplay(t *testing.T) {
	for _, tc := range []struct {
		name                                  string
		public, idor, token, blocked, proxied bool
		want                                  dualverify.Verdict
		defects                               int
	}{
		{"idor", false, true, false, false, true, dualverify.Verified, 0},
		{"protected", false, false, false, false, true, dualverify.ControlsHold, 0},
		{"public", true, true, false, false, true, dualverify.FalsePositive, 0},
		{"expired accepted", false, false, true, false, true, dualverify.ControlsHold, 1},
		{"strict out of scope", false, true, false, true, true, dualverify.Inconclusive, 0},
		{"unrecorded idor", false, true, false, false, false, dualverify.Inconclusive, 0},
		{"unrecorded protected", false, false, false, false, false, dualverify.Inconclusive, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secrets := dualVerifyTestSecrets()
			var mu sync.Mutex
			var auths []string
			marker := "artex-mark-local-private"
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				mu.Lock()
				auths = append(auths, auth)
				mu.Unlock()
				if strings.Contains(auth, "{{") {
					t.Error("unresolved credential sent")
				}
				if r.URL.Path != "/private/a-resource" {
					t.Errorf("path %s", r.URL.Path)
				}
				if auth == "Bearer "+secrets["A"] || (auth == "" && tc.public) || (auth == "Bearer "+secrets["B"] && tc.idor) || (auth == "Bearer "+secrets["B_expired"] && tc.token) {
					w.WriteHeader(200)
					io.WriteString(w, marker)
					return
				}
				w.WriteHeader(403)
			}))
			defer backend.Close()
			p := dualVerifyTestPlan(t, backend.URL, false, tc.token, false)
			scope := func(string) (dualverify.Scope, bool) {
				if tc.blocked {
					return dualverify.ScopeOut, true
				}
				return dualverify.ScopeIn, false
			}
			// The true flag models recording metadata, not a real proxy: evaluator
			// verdict tests must use trusted observations. Direct-mode honesty is separate.
			o, err := runDualVerify(context.Background(), backend.Client(), p, secrets, scope, tc.proxied)
			if err != nil {
				t.Fatal(err)
			}
			r, err := dualverify.Evaluate(p, o)
			if err != nil {
				t.Fatal(err)
			}
			if r.Verdict != tc.want || len(r.TokenDefects) != tc.defects {
				t.Fatalf("%+v", r)
			}
			probe := dualVerifyObservation(t, o, "probe")
			if probe.ProxyBypass == tc.proxied {
				t.Fatalf("proxy honesty: %+v", probe)
			}
			if tc.blocked {
				if !probe.NotExecuted || !probe.OutOfScope {
					t.Fatal(probe)
				}
				mu.Lock()
				n := len(auths)
				mu.Unlock()
				if n != 0 {
					t.Fatalf("sent %d blocked requests", n)
				}
			} else {
				mu.Lock()
				n := len(auths)
				first := ""
				if n > 0 {
					first = auths[0]
				}
				mu.Unlock()
				if n < 3 || first != "" {
					t.Fatalf("public auth/count %q %d", first, n)
				}
			}
			if tc.token {
				for _, id := range []string{"B_revoked", "B_wrong_issuer"} {
					if !dualVerifyObservation(t, o, id).NotExecuted {
						t.Fatal("fabricated credential", id)
					}
				}
			}
			report := dualverify.Report(r, p)
			for _, secret := range secrets {
				if strings.Contains(report, secret) {
					t.Fatal("credential leaked into report")
				}
			}
			for _, token := range []string{"{{A_AUTH}}", "{{B_AUTH}}"} {
				if !strings.Contains(report, token) {
					t.Fatal("missing placeholder", token)
				}
			}
		})
	}
}

func TestDualVerifyScopeHonesty(t *testing.T) {
	for _, tc := range []struct {
		name    string
		scope   dualverify.Scope
		blocked bool
	}{
		{"warn out", dualverify.ScopeOut, false}, {"empty scope", dualverify.ScopeEmpty, false}, {"strict unavailable", dualverify.ScopeEmpty, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.WriteHeader(200)
				io.WriteString(w, "artex-mark-local-private")
			}))
			defer backend.Close()
			p := dualVerifyTestPlan(t, backend.URL, false, false, false)
			o, err := runDualVerify(context.Background(), backend.Client(), p, dualVerifyTestSecrets(), func(string) (dualverify.Scope, bool) { return tc.scope, tc.blocked }, true)
			if err != nil {
				t.Fatal(err)
			}
			r, err := dualverify.Evaluate(p, o)
			if err != nil || r.Verdict != dualverify.Inconclusive {
				t.Fatalf("%+v %v", r, err)
			}
			probe := dualVerifyObservation(t, o, "probe")
			if probe.Scope != tc.scope || probe.NotExecuted != tc.blocked {
				t.Fatal(probe)
			}
			if tc.blocked && requests != 0 {
				t.Fatal("strict scope sent requests")
			}
		})
	}
}

func TestDualVerifyPlantCleanup(t *testing.T) {
	for _, tc := range []struct {
		name             string
		cancel, failRead bool
	}{
		{"normal", false, false}, {"cancel after plant", true, false}, {"read transport failure", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var mu sync.Mutex
			var methods []string
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				methods = append(methods, r.Method)
				mu.Unlock()
				if r.Method == "PATCH" && tc.cancel {
					cancel()
				}
				if r.Method == "GET" && tc.failRead {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err == nil {
						conn.Close()
					}
					return
				}
				if r.Header.Get("Authorization") != "" && r.Method == "GET" {
					io.WriteString(w, "artex-mark-local-private")
					return
				}
				w.WriteHeader(204)
			}))
			defer backend.Close()
			p := dualVerifyTestPlan(t, backend.URL, true, false, false)
			o, err := runDualVerify(ctx, backend.Client(), p, dualVerifyTestSecrets(), func(string) (dualverify.Scope, bool) { return dualverify.ScopeIn, false }, true)
			if (tc.cancel || tc.failRead) && err == nil {
				t.Fatal("expected partial execution warning")
			}
			if !tc.cancel && !tc.failRead && err != nil {
				t.Fatal(err)
			}
			cleanup := dualVerifyObservation(t, o, "cleanup")
			if cleanup.NotExecuted || cleanup.Status != 204 {
				t.Fatalf("cleanup not attempted: %+v", cleanup)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(methods) < 2 || methods[0] != "PATCH" || methods[len(methods)-1] != "DELETE" {
				t.Fatal(methods)
			}
			r, evalErr := dualverify.Evaluate(p, o)
			if evalErr != nil {
				t.Fatal(evalErr)
			}
			report := dualverify.Report(r, p)
			if !strings.Contains(report, "cleanup：成功响应=true") {
				t.Fatal(report)
			}
		})
	}
}

func TestDualVerifyNoPlantNoCleanup(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("unexpected write")
		}
		w.WriteHeader(403)
	}))
	defer backend.Close()
	p := dualVerifyTestPlan(t, backend.URL, true, false, false)
	for i := range p.Steps {
		if p.Steps[i].ID == "plant" {
			p.Steps[i].Request.URL = "https://blocked.test/plant"
		}
	}
	o, err := runDualVerify(context.Background(), backend.Client(), p, dualVerifyTestSecrets(), func(host string) (dualverify.Scope, bool) {
		if host == "blocked.test" {
			return dualverify.ScopeOut, true
		}
		return dualverify.ScopeIn, false
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"plant", "cleanup"} {
		if !dualVerifyObservation(t, o, id).NotExecuted {
			t.Fatal("write attempted", id)
		}
	}
}

func TestDualVerifyRedirectDoesNotForwardCredentials(t *testing.T) {
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("followed redirect to unchecked target") }))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, http.StatusFound) }))
	defer origin.Close()
	p := dualVerifyTestPlan(t, origin.URL, false, false, false)
	o, err := runDualVerify(context.Background(), origin.Client(), p, dualVerifyTestSecrets(), func(string) (dualverify.Scope, bool) { return dualverify.ScopeIn, false }, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range o {
		if v.Status != 302 {
			t.Fatal(v)
		}
	}
	r, err := dualverify.Evaluate(p, o)
	if err != nil || r.Verdict != dualverify.Inconclusive {
		t.Fatalf("%+v %v", r, err)
	}
}

type dualVerifyRoundTripper func(*http.Request) (*http.Response, error)

func (f dualVerifyRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDualVerifyReplayFailures(t *testing.T) {
	for _, tc := range []struct {
		name      string
		transport dualVerifyRoundTripper
	}{
		{"network error", func(r *http.Request) (*http.Response, error) {
			return nil, errors.New("must-not-leak-" + r.Header.Get("Authorization"))
		}},
		{"oversize response", func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", (2<<20)+1))), Header: make(http.Header)}, nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := dualVerifyTestPlan(t, "https://example.test", false, false, false)
			o, err := runDualVerify(context.Background(), &http.Client{Transport: tc.transport}, p, dualVerifyTestSecrets(), func(string) (dualverify.Scope, bool) { return dualverify.ScopeIn, false }, true)
			if err == nil {
				t.Fatal("missing error")
			}
			for _, s := range dualVerifyTestSecrets() {
				if strings.Contains(err.Error(), s) {
					t.Fatal("error leaked secret")
				}
			}
			r, evalErr := dualverify.Evaluate(p, o)
			if evalErr != nil || r.Verdict != dualverify.Inconclusive {
				t.Fatalf("%+v %v", r, evalErr)
			}
		})
	}
	p := dualVerifyTestPlan(t, "https://example.test", false, false, false)
	if _, err := runDualVerify(context.Background(), nil, p, nil, nil, false); err == nil {
		t.Fatal("expected missing dependencies error")
	}
	p.Steps[2].Request.URL = "http://[invalid"
	c := &http.Client{Transport: dualVerifyRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 403, Body: http.NoBody, Header: make(http.Header)}, nil
	})}
	o, err := runDualVerify(context.Background(), c, p, dualVerifyTestSecrets(), func(string) (dualverify.Scope, bool) { return dualverify.ScopeIn, false }, true)
	if err == nil || !dualVerifyObservation(t, o, "probe").NotExecuted {
		t.Fatal("malformed request not refused")
	}
}

func TestDualVerifyClientAndSchema(t *testing.T) {
	for _, proxy := range []string{"http://[invalid", "socks5://proxy.test", "relative"} {
		if _, err := dualVerifyClient(proxy, ""); err == nil {
			t.Fatal("invalid proxy accepted", proxy)
		}
	}
	if _, err := dualVerifyClient("", "/no/such/artex-test-ca.pem"); err == nil {
		t.Fatal("invalid CA accepted")
	}
	c, err := dualVerifyClient("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseIdleConnections()
	if c.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("direct client uses environment proxy")
	}
	schema := dualVerifySchema()
	raw, err := json.Marshal(schema)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"target", "plant", "cleanup", "a_credential_id", "b_credential_id", "b_expired_credential_id", "b_revoked_credential_id", "b_wrong_issuer_credential_id", "b_other_tenant_credential_id", "resource_id", "read", "write", "session_token", "tenant_role", "allow_write", "asset_ids", "finding_id"} {
		if !strings.Contains(string(raw), `"`+key+`"`) {
			t.Fatal("schema missing", key)
		}
	}
}

func TestDualVerifyTemplateValidation(t *testing.T) {
	valid := dualverify.Request{Method: "GET", URL: "https://example.test/{{RESOURCE_ID}}", Headers: map[string]string{"Authorization": "Bearer {{AUTH}}"}}
	if err := validateDualVerifyTemplate(valid, false); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		edit  func(*dualverify.Request)
		write bool
	}{
		{"no auth", func(r *dualverify.Request) { r.Headers = nil }, false},
		{"duplicate auth", func(r *dualverify.Request) { r.Headers["X-Auth"] = "{{AUTH}}" }, false},
		{"auth URL", func(r *dualverify.Request) { r.URL += "?token={{AUTH}}" }, false},
		{"auth body", func(r *dualverify.Request) { r.Body = "{{AUTH}}" }, false},
		{"userinfo", func(r *dualverify.Request) { r.URL = "https://user:pass@example.test" }, false},
		{"host override", func(r *dualverify.Request) { r.Headers["Host"] = "outside.test" }, false},
		{"proxy auth", func(r *dualverify.Request) { r.Headers["Proxy-Authorization"] = "override" }, false},
		{"trace override", func(r *dualverify.Request) { r.Headers[dualVerifyTraceHeader] = "override" }, false},
		{"actor placeholder", func(r *dualverify.Request) { r.Headers["Authorization"] = "{{B_AUTH}}" }, false},
		{"unbounded cleanup", func(r *dualverify.Request) { r.Method = "DELETE" }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := valid
			r.Headers = map[string]string{"Authorization": "Bearer {{AUTH}}"}
			tc.edit(&r)
			if err := validateDualVerifyTemplate(r, tc.write); err == nil {
				t.Fatal("unsafe template accepted")
			}
		})
	}
	secrets := dualVerifyTestSecrets()
	for _, input := range []any{map[string]any{"body": "prefix " + secrets["A"]}, []any{map[string]any{secrets["B"]: "value"}}} {
		if !dualVerifyInputHasSecret(input, secrets) {
			t.Fatal("secret not detected")
		}
	}
	if dualVerifyInputHasSecret(map[string]any{"headers": map[string]any{"Authorization": "{{AUTH}}"}}, secrets) {
		t.Fatal("safe template rejected")
	}
}

func TestDualVerifyTraceMatching(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want bool
	}{
		{"GET / HTTP/1.1\r\nX-Artex-Dualverify: marker:probe\r\n\r\n", true},
		{"GET / HTTP/1.1\nx-artex-dualverify: marker:probe\n\n", true},
		{"GET / HTTP/1.1\nX-Artex-Dualverify: marker:owner\n\n", false},
		{"GET / HTTP/1.1\n\nX-Artex-Dualverify: marker:probe", false},
		{"GET / HTTP/1.1\nX-Artex-Dualverify: marker:probe\nX-Artex-Dualverify: marker:probe\n\n", false},
	} {
		if got := dualVerifyTraceMatches(tc.raw, "marker:probe"); got != tc.want {
			t.Errorf("match=%t want=%t", got, tc.want)
		}
	}
}
