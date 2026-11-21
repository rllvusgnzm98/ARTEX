package traffic

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// PaceProxy is a forward-only HTTP/HTTPS proxy: it applies the shared per-host
// Pacer to agent egress and forwards without MITM/recording, chaining to an
// optional upstream proxy (http/https/socks5) or dialing directly. Cleartext
// HTTP is paced per request; HTTPS (CONNECT) is paced per connection, since a
// non-decrypting proxy cannot see individual requests inside TLS.
type PaceProxy struct {
	pace      atomic.Pointer[Pacer]
	upstream  atomic.Pointer[url.URL]
	srv       *http.Server
	ln        net.Listener
	transport *http.Transport
	closed    chan struct{}
	closeOnce sync.Once
}

func NewPaceProxy(addr string) (*PaceProxy, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	pp := &PaceProxy{ln: ln, closed: make(chan struct{})}
	pp.transport = &http.Transport{
		Proxy:             func(*http.Request) (*url.URL, error) { return pp.upstream.Load(), nil },
		ForceAttemptHTTP2: false,
	}
	pp.srv = &http.Server{Handler: pp}
	return pp, nil
}

func (pp *PaceProxy) Start() error {
	err := pp.srv.Serve(pp.ln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (pp *PaceProxy) Addr() string { return pp.ln.Addr().String() }

func (pp *PaceProxy) Close() error {
	pp.closeOnce.Do(func() { close(pp.closed) })
	return pp.srv.Close()
}

func (pp *PaceProxy) SetHostPacer(p *Pacer) { pp.pace.Store(p) }

func (pp *PaceProxy) SetUpstreamProxy(raw string) error {
	if strings.TrimSpace(raw) == "" {
		pp.upstream.Store(nil)
		return nil
	}
	u, err := ValidateProxyURL(raw)
	if err != nil {
		return err
	}
	if u.Port() == "" {
		if dp := defaultProxyPort(u.Scheme); dp != "" {
			u.Host = net.JoinHostPort(u.Host, dp)
		}
	}
	pp.upstream.Store(u)
	return nil
}

// defaultProxyPort is the implicit port for an upstream proxy URL that omits one;
// ValidateProxyURL accepts portless URLs but a TCP/SOCKS dialer needs a port.
func defaultProxyPort(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	case "socks5", "socks5h":
		return "1080"
	}
	return ""
}

func (pp *PaceProxy) UpstreamProxy() string {
	if up := pp.upstream.Load(); up != nil {
		return up.String()
	}
	return ""
}

func (pp *PaceProxy) paceHost(ctx context.Context, host string) {
	p := pp.pace.Load()
	if p == nil || host == "" || isLoopback(host) {
		return
	}
	p.wait(ctx, host, pp.closed)
}

func (pp *PaceProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		pp.paceHost(r.Context(), hostnameOnly(r.Host))
		pp.handleConnect(w, r)
		return
	}
	pp.paceHost(r.Context(), r.URL.Hostname())
	pp.handleHTTP(w, r)
}

func hostnameOnly(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return hostport
}

func removePaceProxyHopHeaders(h http.Header) {
	for _, value := range h.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			h.Del(strings.TrimSpace(token))
		}
	}
	for _, name := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		h.Del(name)
	}
}

func (pp *PaceProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	removePaceProxyHopHeaders(outReq.Header)
	resp, err := pp.transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	removePaceProxyHopHeaders(resp.Header)
	for name, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (pp *PaceProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	dst, err := pp.dialTarget(r.Context(), r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		dst.Close()
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		dst.Close()
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(dst, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, dst); done <- struct{}{} }()
	<-done
	client.Close()
	dst.Close()
}

func (pp *PaceProxy) dialTarget(ctx context.Context, hostport string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 30 * time.Second}
	up := pp.upstream.Load()
	if up == nil {
		return d.DialContext(ctx, "tcp", hostport)
	}
	switch up.Scheme {
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if up.User != nil {
			pw, _ := up.User.Password()
			auth = &proxy.Auth{User: up.User.Username(), Password: pw}
		}
		sd, err := proxy.SOCKS5("tcp", up.Host, auth, d)
		if err != nil {
			return nil, err
		}
		if cd, ok := sd.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, "tcp", hostport)
		}
		return sd.Dial("tcp", hostport)
	case "http", "https":
		return pp.dialViaHTTPConnect(ctx, up, hostport)
	default:
		return nil, fmt.Errorf("unsupported upstream scheme %q", up.Scheme)
	}
}

func (pp *PaceProxy) dialViaHTTPConnect(ctx context.Context, up *url.URL, hostport string) (net.Conn, error) {
	conn, err := (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, "tcp", up.Host)
	if err != nil {
		return nil, err
	}
	// Bound the CONNECT handshake (CONNECT request + response, plus any TLS to an
	// https upstream): request contexts carry no deadline, so without this a stalled
	// upstream would block ReadResponse forever and leak the conn + goroutine. The
	// deadline is cleared before returning so the established tunnel is not time-boxed.
	handshake := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(handshake) {
		handshake = d
	}
	if err := conn.SetDeadline(handshake); err != nil {
		conn.Close()
		return nil, err
	}
	if up.Scheme == "https" {
		conn = tls.Client(conn, &tls.Config{ServerName: up.Hostname()})
	}
	auth := ""
	if up.User != nil {
		pw, _ := up.User.Password()
		auth = "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(up.User.Username()+":"+pw)) + "\r\n"
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", hostport, hostport, auth); err != nil {
		conn.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("upstream CONNECT: %s", resp.Status)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}
