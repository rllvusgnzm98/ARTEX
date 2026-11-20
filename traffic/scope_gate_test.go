package traffic

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func startScopeProxy(t *testing.T) (*Traffic, string) {
	t.Helper()
	var last error
	for i := 0; i < 5; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			last = err
			continue
		}
		addr := ln.Addr().String()
		ln.Close()
		tr, err := Open(t.TempDir(), addr)
		if err != nil {
			last = err
			continue
		}
		errCh := make(chan error, 1)
		go func() { errCh <- tr.Start() }()
		t.Cleanup(func() { _ = tr.Close() })
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			c, dialErr := net.DialTimeout("tcp", addr, 200*time.Millisecond)
			if dialErr == nil {
				c.Close()
				return tr, tr.ProxyAddr()
			}
			select {
			case startErr := <-errCh:
				if startErr != nil {
					last = startErr
				}
				deadline = time.Time{}
			default:
				time.Sleep(20 * time.Millisecond)
			}
		}
		if last == nil {
			last = fmt.Errorf("proxy %s did not accept", addr)
		}
	}
	t.Fatalf("start proxy: %v", last)
	return nil, ""
}

func proxyClient(proxyURL string) *http.Client {
	u, err := url.Parse(proxyURL)
	if err != nil {
		panic(err)
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(u),
			DisableKeepAlives: true,
		},
	}
}

type gateSnap struct {
	status int
	ct     string
	body   []byte
}

func getVia(t *testing.T, client *http.Client, rawURL string) gateSnap {
	t.Helper()
	resp, err := client.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return gateSnap{status: resp.StatusCode, ct: resp.Header.Get("Content-Type"), body: body}
}

func TestScopeGateBlocksForwardsAndNilMatchesBaseline(t *testing.T) {
	var hits atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("origin-ok"))
	}))
	t.Cleanup(origin.Close)

	tr, proxyURL := startScopeProxy(t)
	client := proxyClient(proxyURL)
	baseline := getVia(t, client, origin.URL+"/x")
	if baseline.status != http.StatusOK || !bytes.Equal(baseline.body, []byte("origin-ok")) {
		t.Fatalf("baseline = %d %q %q", baseline.status, baseline.ct, baseline.body)
	}
	if hits.Load() != 1 {
		t.Fatalf("baseline hits=%d", hits.Load())
	}

	const denied = "越界主机 127.0.0.1"
	tr.SetHostGate(func(host string) error {
		if host == "127.0.0.1" {
			return fmt.Errorf("%s", denied)
		}
		return nil
	})
	blocked := getVia(t, client, origin.URL+"/x")
	if blocked.status != http.StatusForbidden {
		t.Fatalf("越界 status=%d body=%q", blocked.status, blocked.body)
	}
	if blocked.ct != "text/plain; charset=utf-8" {
		t.Fatalf("越界 Content-Type=%q", blocked.ct)
	}
	if !bytes.Equal(blocked.body, []byte(denied)) {
		t.Fatalf("越界 body=%q", blocked.body)
	}
	if hits.Load() != 1 {
		t.Fatalf("越界仍打到上游 hits=%d", hits.Load())
	}

	tr.SetHostGate(func(string) error { return nil })
	allowed := getVia(t, client, origin.URL+"/x")
	if allowed.status != baseline.status || allowed.ct != baseline.ct || !bytes.Equal(allowed.body, baseline.body) {
		t.Fatalf("放行 = %d %q %q, baseline = %d %q %q", allowed.status, allowed.ct, allowed.body, baseline.status, baseline.ct, baseline.body)
	}

	tr.SetHostGate(nil)
	cleared := getVia(t, client, origin.URL+"/x")
	if cleared.status != baseline.status || cleared.ct != baseline.ct || !bytes.Equal(cleared.body, baseline.body) {
		t.Fatalf("nil gate = %d %q %q, baseline = %d %q %q", cleared.status, cleared.ct, cleared.body, baseline.status, baseline.ct, baseline.body)
	}
	if hits.Load() != 3 {
		t.Fatalf("放行与 nil gate 应各打一次上游 hits=%d", hits.Load())
	}
}

func TestScopeGatePassthroughDeniedReturnsReasonAndAllowStillDials(t *testing.T) {
	tr, proxyURL := startScopeProxy(t)
	proxyAddr := proxyURL[len("http://"):]
	// localhost 才能带 DNS SAN。上游同时听 127.0.0.1 和 ::1，放行后的拨号无论走哪边都能数到。
	ln4, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln4.Addr().(*net.TCPAddr).Port
	var accepts atomic.Int32
	serveAccepts(t, ln4, &accepts)
	if ln6, err6 := net.Listen("tcp", net.JoinHostPort("::1", strconv.Itoa(port))); err6 == nil {
		serveAccepts(t, ln6, &accepts)
	}
	target := net.JoinHostPort("localhost", strconv.Itoa(port))
	tr.pass.Store("localhost", struct{}{})

	const denied = "RoE 授权范围检查：越界主机 localhost"
	var mu sync.Mutex
	var seen []string
	tr.SetHostGate(func(host string) error {
		mu.Lock()
		seen = append(seen, host)
		mu.Unlock()
		return fmt.Errorf("%s", denied)
	})
	blocked := getVia(t, trustedProxyClient(t, tr, proxyURL, "localhost"), "https://"+target+"/x")
	if blocked.status != http.StatusForbidden {
		t.Fatalf("透传越界 status=%d body=%q", blocked.status, blocked.body)
	}
	if !bytes.Contains(blocked.body, []byte("RoE")) || !bytes.Contains(blocked.body, []byte(denied)) {
		t.Fatalf("透传越界正文缺少闸门原因: %q", blocked.body)
	}
	time.Sleep(200 * time.Millisecond)
	if accepts.Load() != 0 {
		t.Fatalf("越界仍拨了上游 accepts=%d", accepts.Load())
	}
	mu.Lock()
	gotSeen := append([]string(nil), seen...)
	mu.Unlock()
	if len(gotSeen) == 0 {
		t.Fatal("透传越界没有调用 gate")
	}
	for _, host := range gotSeen {
		if host != "localhost" {
			t.Fatalf("gate host = %#v", gotSeen)
		}
	}

	// 放行必须回到原来的 pass 表行为：仍然透传，并且会拨上游。
	tr.SetHostGate(func(string) error { return nil })
	status, err := rawCONNECT(proxyAddr, target)
	if err != nil {
		t.Fatalf("放行 CONNECT: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("放行 CONNECT status=%d, want 200", status)
	}
	deadline := time.Now().Add(time.Second)
	for accepts.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	allowedAccepts := accepts.Load()
	if allowedAccepts == 0 {
		t.Fatal("gate 放行后透传没有拨到上游")
	}

	tr.SetHostGate(nil)
	status, err = rawCONNECT(proxyAddr, target)
	if err != nil {
		t.Fatalf("nil gate CONNECT: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("nil gate CONNECT status=%d, want 200", status)
	}
	deadline = time.Now().Add(time.Second)
	for accepts.Load() <= allowedAccepts && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if accepts.Load() <= allowedAccepts {
		t.Fatal("nil gate 透传没有拨到上游")
	}
}

func serveAccepts(t *testing.T, ln net.Listener, accepts *atomic.Int32) {
	t.Helper()
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			c.Close()
		}
	}()
}

func trustedProxyClient(t *testing.T, tr *Traffic, proxyURL, serverName string) *http.Client {
	t.Helper()
	pemBytes, err := os.ReadFile(tr.CACertPath())
	if err != nil {
		t.Fatalf("read CA %s: %v", tr.CACertPath(), err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatalf("CA %s 不是 PEM", tr.CACertPath())
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(u),
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				ServerName: serverName,
				NextProtos: []string{"http/1.1"},
			},
			DisableKeepAlives: true,
			ForceAttemptHTTP2: false,
		},
	}
}

func rawCONNECT(proxyAddr, target string) (int, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		return 0, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}
