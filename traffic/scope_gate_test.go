package traffic

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestScopeGatePassthroughConnectDoesNotDial(t *testing.T) {
	tr, proxyURL := startScopeProxy(t)
	proxyAddr := proxyURL[len("http://"):]
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var accepts atomic.Int32
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
	target := ln.Addr().String()
	tr.pass.Store("127.0.0.1", struct{}{})

	var seen []string
	tr.SetHostGate(func(host string) error {
		seen = append(seen, host)
		return fmt.Errorf("越界 %s", host)
	})
	status, err := rawCONNECT(proxyAddr, target)
	if err != nil {
		t.Fatalf("blocked CONNECT: %v", err)
	}
	if status != http.StatusBadGateway {
		t.Fatalf("透传越界 status=%d, want 502", status)
	}
	time.Sleep(200 * time.Millisecond)
	if accepts.Load() != 0 {
		t.Fatalf("越界仍拨了上游 accepts=%d", accepts.Load())
	}
	if len(seen) == 0 {
		t.Fatal("透传越界没有调用 gate")
	}
	for _, host := range seen {
		if host != "127.0.0.1" {
			t.Fatalf("gate host = %#v", seen)
		}
	}

	tr.SetHostGate(nil)
	status, err = rawCONNECT(proxyAddr, target)
	if err != nil {
		t.Fatalf("nil gate CONNECT: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("nil gate CONNECT status=%d, want 200", status)
	}
	deadline := time.Now().Add(time.Second)
	for accepts.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if accepts.Load() == 0 {
		t.Fatal("nil gate 透传没有拨到上游")
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
