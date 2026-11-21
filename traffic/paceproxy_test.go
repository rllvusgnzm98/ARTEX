package traffic

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func startPaceProxy(t *testing.T) *PaceProxy {
	t.Helper()
	pp, err := NewPaceProxy("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- pp.Start() }()
	t.Cleanup(func() {
		if err := pp.Close(); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
		pp.transport.CloseIdleConnections()
	})
	return pp
}

func paceProxyClient(t *testing.T, pp *PaceProxy) *http.Client {
	t.Helper()
	u, err := url.Parse("http://" + pp.Addr())
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{
		Proxy:           http.ProxyURL(u),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}
}

func assertPaceProxyBody(t *testing.T, client *http.Client, target, want string) {
	t.Helper()
	resp, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != want {
		t.Fatalf("response = %d %q, want 200 %q", resp.StatusCode, body, want)
	}
}

func TestPaceProxyForwardsHTTP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "cleartext backend")
	}))
	defer backend.Close()
	pp := startPaceProxy(t)
	assertPaceProxyBody(t, paceProxyClient(t, pp), backend.URL, "cleartext backend")
}

func TestPaceProxyTunnelsHTTPS(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "TLS backend")
	}))
	defer backend.Close()
	pp := startPaceProxy(t)
	assertPaceProxyBody(t, paceProxyClient(t, pp), backend.URL, "TLS backend")
}

func TestPaceProxyChainsUpstreamConnect(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "chained TLS backend")
	}))
	defer backend.Close()
	upstream := startPaceProxy(t)
	pp := startPaceProxy(t)
	if err := pp.SetUpstreamProxy("http://" + upstream.Addr()); err != nil {
		t.Fatal(err)
	}
	assertPaceProxyBody(t, paceProxyClient(t, pp), backend.URL, "chained TLS backend")
}

func TestPaceProxyPacesNonLoopbackHost(t *testing.T) {
	pp := startPaceProxy(t)
	pp.SetHostPacer(NewPacer(20, 1))
	start := time.Now()
	for i := 0; i < 3; i++ {
		pp.paceHost(context.Background(), "a.example")
	}
	if elapsed := time.Since(start); elapsed < 90*time.Millisecond {
		t.Fatalf("three paced requests took %v, want at least 90ms", elapsed)
	}
	// A full second of queued work makes accidental pacing distinguishable.
	pp.SetHostPacer(NewPacer(1, 1))
	pp.pace.Load().reserve("127.0.0.1")
	start = time.Now()
	pp.paceHost(context.Background(), "127.0.0.1")
	if elapsed := time.Since(start); elapsed >= 500*time.Millisecond {
		t.Fatalf("loopback was paced for %v", elapsed)
	}
	pp.pace.Load().reserve("a.example")
	pp.SetHostPacer(nil)
	start = time.Now()
	pp.paceHost(context.Background(), "a.example")
	if elapsed := time.Since(start); elapsed >= 500*time.Millisecond {
		t.Fatalf("disabled pacer waited for %v", elapsed)
	}
}

func TestPaceProxyUpstreamSetting(t *testing.T) {
	pp := startPaceProxy(t)
	if got := pp.UpstreamProxy(); got != "" {
		t.Fatalf("initial upstream = %q", got)
	}
	const upstream = "http://127.0.0.1:8080"
	if err := pp.SetUpstreamProxy(upstream); err != nil {
		t.Fatal(err)
	}
	if err := pp.SetUpstreamProxy("invalid://host"); err == nil {
		t.Fatal("invalid upstream was accepted")
	}
	if got := pp.UpstreamProxy(); got != upstream {
		t.Fatalf("upstream after rejected change = %q, want %q", got, upstream)
	}
	if err := pp.SetUpstreamProxy("  "); err != nil {
		t.Fatal(err)
	}
	if got := pp.UpstreamProxy(); got != "" {
		t.Fatalf("cleared upstream = %q", got)
	}
}

func TestPaceProxyHopHeaders(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Hop") != "" || r.Header.Get("Proxy-Authorization") != "" {
			t.Error("hop-by-hop request headers reached backend")
		}
		w.Header().Set("Connection", "X-Response-Hop")
		w.Header().Set("X-Response-Hop", "private")
		w.Header().Set("X-End-To-End", "retained")
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()
	pp := startPaceProxy(t)
	req, err := http.NewRequest(http.MethodGet, backend.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Connection", "X-Hop")
	req.Header.Set("X-Hop", "private")
	req.Header.Set("Proxy-Authorization", "Basic private")
	resp, err := paceProxyClient(t, pp).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.Header.Get("X-Response-Hop") != "" || resp.Header.Get("X-End-To-End") != "retained" {
		t.Fatalf("unexpected forwarded headers: %v", resp.Header)
	}
}

func TestPaceProxyHTTPError(t *testing.T) {
	pp := startPaceProxy(t)
	req := httptest.NewRequest(http.MethodGet, "unsupported://example.com/", nil)
	w := httptest.NewRecorder()
	pp.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", w.Code)
	}
}

func TestPaceProxyUpstreamDefaultPort(t *testing.T) {
	pp, err := NewPaceProxy("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pp.Close()
	for raw, want := range map[string]string{
		"http://proxy":      "proxy:80",
		"https://proxy":     "proxy:443",
		"socks5://proxy":    "proxy:1080",
		"http://proxy:3128": "proxy:3128",
		"http://[::1]":      "[::1]:80",
		"http://[::1]:3128": "[::1]:3128",
	} {
		if err := pp.SetUpstreamProxy(raw); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if got := pp.upstream.Load().Host; got != want {
			t.Fatalf("%s: host %q, want %q", raw, got, want)
		}
	}
}
