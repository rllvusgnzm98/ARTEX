package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// AttachStableWebFetch 关掉 agentcore 默认 EnableWebFetch（norma v0.4.3 把
// User-Agent 写死为 norma/0.4），改把官方 WebFetch 配上本任务稳定 UA 后装进
// Tools，并在回包出口包 untrusted-data。ua 为空则沿用官方默认请求头。
func AttachStableWebFetch(opts *agentcore.Options, ua string) {
	if opts == nil {
		return
	}
	opts.EnableWebFetch = false
	cfg := actool.WebFetchConfig{
		Proxy:       opts.WebFetchProxy,
		CACert:      opts.WebFetchCACert,
		InsecureTLS: opts.WebFetchInsecureTLS,
	}
	opts.Tools = append(opts.Tools, guardPanic(wrapTargetSideOutput(NewWebFetchWithUA(cfg, ua))))
}

// NewWebFetchWithUA 返回名为 WebFetch 的官方工具。实际发出的请求带上 ua
// （与 PickUA / $ARTEX_UA 同一套按任务稳定分配，任务内不更换）。
// 响应格式仍交给官方 WebFetch 处理。ua 为空时直接返回官方工具。
func NewWebFetchWithUA(cfg actool.WebFetchConfig, ua string) actool.CoreTool {
	inner := actool.NewWebFetch(cfg)
	if ua == "" {
		return inner
	}
	return &uaWebFetch{
		inner:    inner,
		replay:   actool.NewWebFetch(actool.WebFetchConfig{}),
		client:   newWebFetchClient(cfg),
		ua:       ua,
		proxy:    cfg.Proxy,
		insecure: cfg.InsecureTLS,
	}
}

type uaWebFetch struct {
	inner    actool.CoreTool
	replay   actool.CoreTool
	client   *http.Client
	ua       string
	proxy    string
	insecure bool
}

func (t *uaWebFetch) Name() string                              { return t.inner.Name() }
func (t *uaWebFetch) Description() string                       { return t.inner.Description() }
func (t *uaWebFetch) Prompt() string                            { return t.inner.Prompt() }
func (t *uaWebFetch) InputSchema() map[string]any               { return t.inner.InputSchema() }
func (t *uaWebFetch) IsReadOnly(in json.RawMessage) bool        { return t.inner.IsReadOnly(in) }
func (t *uaWebFetch) IsConcurrencySafe(in json.RawMessage) bool { return t.inner.IsConcurrencySafe(in) }
func (t *uaWebFetch) CheckPermissions(ctx context.Context, in json.RawMessage, pc permission.Context) permission.Decision {
	return t.inner.CheckPermissions(ctx, in, pc)
}

func (t *uaWebFetch) Call(ctx context.Context, input json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	var in struct {
		URL     string `json:"url"`
		Extract bool   `json:"extract"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return t.inner.Call(ctx, input, tc)
	}
	if !strings.HasPrefix(in.URL, "http://") && !strings.HasPrefix(in.URL, "https://") {
		return t.inner.Call(ctx, input, tc)
	}
	if webFetchStaticAsset(in.URL) {
		return t.inner.Call(ctx, input, tc)
	}

	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, in.URL, nil)
	if err != nil {
		return t.inner.Call(ctx, input, tc)
	}
	// 接到官方请求头上：覆盖 norma 内置的 "norma/0.4"，改用按任务稳定 UA。
	req.Header.Set("User-Agent", t.ua)
	resp, err := t.client.Do(req)
	if err != nil && t.proxy != "" && webFetchProxyLikelyErr(err) {
		direct := newWebFetchClient(actool.WebFetchConfig{InsecureTLS: t.insecure})
		if r2, e2 := http.NewRequestWithContext(cctx, http.MethodGet, in.URL, nil); e2 == nil {
			r2.Header.Set("User-Agent", t.ua)
			if resp2, err2 := direct.Do(r2); err2 == nil {
				resp, err = resp2, nil
			} else {
				err = err2
			}
		}
	}
	if err != nil {
		return actool.Errorf("Error fetching URL: " + err.Error()), nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	hdr := resp.Header.Clone()
	status := resp.StatusCode

	orig, err := url.Parse(in.URL)
	if err != nil {
		return actool.Errorf("Error: " + err.Error()), nil
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, vs := range hdr {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	replayURL := srv.URL + orig.RequestURI()
	replayIn, _ := json.Marshal(map[string]any{"url": replayURL, "extract": in.Extract})
	res, callErr := t.replay.Call(ctx, replayIn, tc)
	if callErr != nil {
		return res, callErr
	}
	origin := orig.Scheme + "://" + orig.Host
	for i, b := range res.Content {
		if b.Type == llm.BlockText {
			text := b.Text
			text = strings.ReplaceAll(text, replayURL, in.URL)
			text = strings.ReplaceAll(text, srv.URL, origin)
			res.Content[i].Text = text
		}
	}
	return res, nil
}

// newWebFetchClient 复刻 norma v0.4.3 tool.newFetchClient：尊重官方
// WebFetchConfig 的 Proxy / CACert / InsecureTLS。
func newWebFetchClient(cfg actool.WebFetchConfig) *http.Client {
	if cfg.Proxy == "" && !cfg.InsecureTLS && cfg.CACert == "" {
		return &http.Client{}
	}
	tr := &http.Transport{}
	if cfg.Proxy != "" {
		if pu, err := url.Parse(cfg.Proxy); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	switch {
	case cfg.InsecureTLS:
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	case cfg.CACert != "":
		if pem, err := os.ReadFile(cfg.CACert); err == nil {
			pool, _ := x509.SystemCertPool()
			if pool == nil {
				pool = x509.NewCertPool()
			}
			if pool.AppendCertsFromPEM(pem) {
				tr.TLSClientConfig = &tls.Config{RootCAs: pool}
			}
		}
	}
	return &http.Client{Transport: tr}
}

func webFetchProxyLikelyErr(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	for _, n := range []string{"no such host", "context canceled", "context deadline", "timeout"} {
		if strings.Contains(s, n) {
			return false
		}
	}
	for _, p := range []string{
		"eof", "connection reset", "connection refused", "proxyconnect",
		"broken pipe", "forcibly closed", "malformed", "http2", "http/2",
		"tls:", "protocol error",
	} {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func webFetchStaticAsset(rawURL string) bool {
	path := rawURL
	if u, err := url.Parse(rawURL); err == nil {
		path = u.Path
	}
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		path = path[i+1:]
	}
	dot := strings.LastIndexByte(path, '.')
	if dot < 0 {
		return false
	}
	switch strings.ToLower(path[dot:]) {
	case ".js", ".mjs", ".cjs", ".css", ".map",
		".png", ".jpg", ".jpeg", ".gif", ".svg",
		".webp", ".avif", ".ico", ".bmp",
		".woff", ".woff2", ".ttf", ".otf", ".eot",
		".wasm", ".mp4", ".webm", ".mp3", ".wav", ".ogg":
		return true
	}
	return false
}
