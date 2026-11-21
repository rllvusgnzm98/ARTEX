package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent/dualverify"
)

const dualVerifyTraceHeader = "X-Artex-Dualverify"

var dualVerifyTokens = map[string]string{
	"A": "{{A_AUTH}}", "B": "{{B_AUTH}}", "B_expired": "{{B_EXPIRED}}",
	"B_revoked": "{{B_REVOKED}}", "B_wrong_issuer": "{{B_WRONG_ISSUER}}",
	"B_other_tenant": "{{B_OTHER_TENANT_AUTH}}",
}

func dualVerifyClient(proxyAddr, caFile string) (*http.Client, error) {
	tr := &http.Transport{}
	if proxyAddr != "" {
		u, err := url.Parse(proxyAddr)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, errors.New("任务代理地址无效，未发送请求")
		}
		tr.Proxy = http.ProxyURL(u)
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, errors.New("无法读取任务代理 CA")
		}
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("任务代理 CA 无效")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool}
	}
	return &http.Client{Transport: tr, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

// runDualVerify 不向调用方回传目标响应或网络错误文本，避免错误 URL/响应回显凭据。
// proxied 是宿主提供的记录路径元数据，不是范围授权。
func runDualVerify(ctx context.Context, client *http.Client, plan dualverify.Plan, secrets map[string]string, scopeOf func(string) (dualverify.Scope, bool), proxied bool) ([]dualverify.Observation, error) {
	if client == nil || scopeOf == nil {
		return nil, errors.New("缺少 HTTP 客户端或范围判定")
	}
	c := *client
	c.Jar = nil
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	var observations []dualverify.Observation
	var failed bool
	planted := false
	for _, step := range plan.Steps {
		o := dualverify.Observation{StepID: step.ID, ProxyBypass: !proxied, Scope: dualverify.ScopeEmpty}
		u, err := url.Parse(step.Request.URL)
		if err != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
			o.NotExecuted = true
			failed = true
			observations = append(observations, o)
			continue
		}
		scope, blocked := scopeOf(u.Hostname())
		o.Scope = scope
		o.OutOfScope = scope == dualverify.ScopeOut
		if blocked || (step.ID == "cleanup" && !planted) || (step.Actor != "public" && secrets[step.Actor] == "") {
			o.NotExecuted = true
			observations = append(observations, o)
			continue
		}
		stepCtx := ctx
		if step.ID == "cleanup" {
			stepCtx = context.WithoutCancel(ctx)
		}
		stepCtx, cancel := context.WithTimeout(stepCtx, 20*time.Second)
		substitute := func(v string) string {
			if token := dualVerifyTokens[step.Actor]; token != "" {
				return strings.ReplaceAll(v, token, secrets[step.Actor])
			}
			return v
		}
		req, err := http.NewRequestWithContext(stepCtx, step.Request.Method, substitute(step.Request.URL), strings.NewReader(substitute(step.Request.Body)))
		if err != nil {
			cancel()
			o.NotExecuted = true
			failed = true
			observations = append(observations, o)
			continue
		}
		for k, v := range step.Request.Headers {
			req.Header.Set(k, substitute(v))
		}
		if step.ID == "plant" {
			planted = true
		}
		resp, err := c.Do(req)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
			resp.Body.Close()
			if readErr == nil && len(body) <= 2<<20 {
				o.Status = resp.StatusCode
				o.MarkerSeen = plan.Marker != "" && strings.Contains(string(body), plan.Marker)
			} else {
				failed = true
			}
		} else {
			failed = true
		}
		cancel()
		observations = append(observations, o)
	}
	if failed {
		return observations, errors.New("部分请求失败或响应超过 2 MiB，相关观察未验证；已尝试执行获准的清理")
	}
	return observations, nil
}
