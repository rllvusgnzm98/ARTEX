package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestQuotaAwareTransportRedactsErrorsAtSource(t *testing.T) {
	rawProxy := "http://proxyuser:supersecret@proxy.internal:8080/gate?token=tok123"
	targetURL := "https://apiuser:apikey@llm.example.test/v1/messages?api_key=sk-leak-999"
	sentinel := errors.New("dial tcp: proxyconnect via " + rawProxy)

	tr := quotaAwareTransport{
		base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return nil, &url.Error{Op: "Post", URL: targetURL, Err: sentinel}
		}),
		rawProxy: rawProxy,
	}
	req, _ := http.NewRequest(http.MethodPost, targetURL, nil)
	_, err := tr.RoundTrip(req)
	if err == nil {
		t.Fatal("expected transport error")
	}
	got := err.Error()
	for _, secret := range []string{"proxyuser", "supersecret", "tok123", "apiuser", "apikey", "sk-leak-999", "/v1/messages"} {
		if strings.Contains(got, secret) {
			t.Fatalf("transport error leaked %q: %s", secret, got)
		}
	}
	for _, keep := range []string{"https://****@llm.example.test/****", "http://****@proxy.internal:8080/****"} {
		if !strings.Contains(got, keep) {
			t.Fatalf("transport error lost masked endpoint %q: %s", keep, got)
		}
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("redacted transport error must preserve errors.Is chain: %v", err)
	}
	var ue *url.Error
	if !errors.As(err, &ue) {
		t.Fatalf("redacted transport error must preserve *url.Error: %v", err)
	}
}

func TestIdleTimeoutReadCloserAbortsHungStream(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()

	// Send one chunk immediately, then hang indefinitely.
	go func() {
		_, _ = pw.Write([]byte("event: ping\n\n"))
	}()

	rc := &idleTimeoutReadCloser{rc: pr, idle: 40 * time.Millisecond}
	defer rc.Close()

	buf := make([]byte, 64)
	n, err := rc.Read(buf)
	if err != nil || string(buf[:n]) != "event: ping\n\n" {
		t.Fatalf("first read = %q err=%v", string(buf[:n]), err)
	}

	start := time.Now()
	_, err = rc.Read(buf)
	if err == nil {
		t.Fatal("expected stream idle timeout on hung pipe")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("idle timeout took too long: %s", time.Since(start))
	}
	if !IsCallTimeout(err) {
		t.Fatalf("StreamIdleTimeoutError must satisfy IsCallTimeout: %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("StreamIdleTimeoutError must unwrap to context.DeadlineExceeded: %v", err)
	}
	var sit *StreamIdleTimeoutError
	if !errors.As(err, &sit) || sit.Idle != 40*time.Millisecond {
		t.Fatalf("expected *StreamIdleTimeoutError{Idle:40ms}, got %v", err)
	}
}

func TestIdleTimeoutReadCloserAllowsSteadyStream(t *testing.T) {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		for i := 0; i < 3; i++ {
			time.Sleep(15 * time.Millisecond)
			_, _ = fmt.Fprintf(pw, "chunk-%d;", i)
		}
	}()

	rc := &idleTimeoutReadCloser{rc: pr, idle: 150 * time.Millisecond}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("steady stream failed: %v", err)
	}
	if string(data) != "chunk-0;chunk-1;chunk-2;" {
		t.Fatalf("got %q", string(data))
	}
}
