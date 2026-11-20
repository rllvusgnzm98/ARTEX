package server

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/config"
)

func gateServe(h http.Handler, method, path, remote, auth string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader("{}")
	}
	req := httptest.NewRequest(method, path, body)
	if remote != "" {
		req.RemoteAddr = remote
	}
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	for _, c := range cookies {
		if c != nil {
			req.AddCookie(c)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func gateCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	return gateNamedCookie(t, rec, gateBypassCookie)
}

func gateNamedCookie(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("响应没有 %s: %s", name, rec.Header().Get("Set-Cookie"))
	return nil
}

func TestGateDetectPreservesBytesAndCounts(t *testing.T) {
	g := newGate(config.GateModeDetect, config.GateSourceDefault, []byte("detect-key"), "")
	s := &Server{gate: g}
	h := s.Handler()
	direct := s.webuiHandler()
	for _, path := range []string{"/", "/dashboard", "/assets/app.js"} {
		got := gateServe(h, http.MethodGet, path, "203.0.113.10:443", "")
		want := gateServe(direct, http.MethodGet, path, "203.0.113.10:443", "")
		if got.Code != want.Code || !bytes.Equal(got.Body.Bytes(), want.Body.Bytes()) {
			t.Fatalf("%s 响应被改写: got %d %q want %d %q", path, got.Code, got.Body.String(), want.Code, want.Body.String())
		}
		if got.Header().Get("Content-Type") != want.Header().Get("Content-Type") {
			t.Fatalf("%s Content-Type 被改写", path)
		}
	}
	st := g.Stats()
	if st.Hits != 3 || st.Allows != 3 || st.Bypasses != 0 || st.Decoys != 0 {
		t.Fatalf("detect 计数 = %+v", st)
	}
	if st.Mode != config.GateModeDetect || st.Source != config.GateSourceDefault {
		t.Fatalf("stats mode/source = %+v", st)
	}
}

func TestGateEnforceDecoyAndPassthrough(t *testing.T) {
	const remote = "203.0.113.20:443"
	g := newGate(config.GateModeEnforce, config.GateSourceEnv, []byte("enforce-key"), "")
	s := &Server{m: &Manager{}, jwtKey: []byte("enforce-key"), gate: g}
	h := s.Handler()
	ui := gateServe(s.webuiHandler(), http.MethodGet, "/secret", remote, "")
	decoy := gateServe(h, http.MethodGet, "/secret", remote, "")
	if decoy.Code != http.StatusNotFound {
		t.Fatalf("诱饵状态码 %d", decoy.Code)
	}
	if ct := decoy.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Fatalf("诱饵 Content-Type %q", ct)
	}
	if decoy.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("诱饵应带 nosniff")
	}
	body := decoy.Body.String()
	if strings.Contains(strings.ToLower(body), "artex") || strings.Contains(body, "前端未内嵌") {
		t.Fatalf("诱饵暴露了产品或真实 404 正文: %q", body)
	}
	if ui.Code == http.StatusNotFound && decoy.Body.Len() != ui.Body.Len() {
		t.Fatalf("诱饵长度 %d 与 webui 404 长度 %d 不一致", decoy.Body.Len(), ui.Body.Len())
	}
	if bytes.Equal(decoy.Body.Bytes(), ui.Body.Bytes()) {
		t.Fatal("诱饵不应等于 webui 原文")
	}

	health := gateServe(h, http.MethodGet, "/api/health", remote, "")
	if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), `"ok":true`) {
		t.Fatalf("/api/health 应直通: %d %s", health.Code, health.Body.String())
	}
	auth := gateServe(h, http.MethodGet, "/api/auth/status", remote, "")
	if auth.Code != http.StatusServiceUnavailable || !strings.Contains(auth.Body.String(), "PostgreSQL") {
		t.Fatalf("/api/auth/status 应直通到数据源错误: %d %s", auth.Code, auth.Body.String())
	}
	if strings.Contains(auth.Body.String(), decoyMessage) {
		t.Fatal("/api/auth/status 被门控改成了诱饵")
	}
	stage := gateServe(h, http.MethodGet, "/s/tok/name.bin", remote, "")
	if stage.Body.String() != "404 page not found\n" {
		t.Fatalf("/s/{token}/{name} 应落到 stage 的 404，got %d %q", stage.Code, stage.Body.String())
	}
	if strings.Contains(stage.Body.String(), decoyMessage) {
		t.Fatal("stage 路径被门控改成了诱饵")
	}

	loop := gateServe(h, http.MethodGet, "/secret", "127.0.0.1:9", "")
	if !bytes.Equal(loop.Body.Bytes(), ui.Body.Bytes()) {
		t.Fatalf("127.0.0.1 应放行，got %q", loop.Body.String())
	}
	v6 := gateServe(h, http.MethodGet, "/secret", "[::1]:9", "")
	if !bytes.Equal(v6.Body.Bytes(), ui.Body.Bytes()) {
		t.Fatalf("::1 应放行，got %q", v6.Body.String())
	}
	st := g.Stats()
	if st.Decoys != 1 || st.Bypasses != 0 || st.Allows < 2 {
		t.Fatalf("enforce 计数 = %+v", st)
	}
}

func TestGateBypassOneTimeExpiryAndCookie(t *testing.T) {
	const remote = "203.0.113.30:9"
	key := []byte("bypass-signing-key")
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	g := newGate(config.GateModeEnforce, config.GateSourceEnv, key, "")
	g.now = func() time.Time { return base }
	g.ttl = time.Minute
	s := &Server{jwtKey: key, gate: g}
	h := s.Handler()
	tok, err := signJWT(key)
	if err != nil {
		t.Fatal(err)
	}
	ui := gateServe(s.webuiHandler(), http.MethodGet, "/", remote, "")

	noAuth := gateServe(h, http.MethodPost, "/api/gate/bypass", remote, "")
	if noAuth.Code != http.StatusUnauthorized || noAuth.Header().Get("Set-Cookie") != "" {
		t.Fatalf("未登录不得签发旁路: %d %q", noAuth.Code, noAuth.Header().Get("Set-Cookie"))
	}

	issued := gateServe(h, http.MethodPost, "/api/gate/bypass", remote, tok)
	if issued.Code != http.StatusOK {
		t.Fatalf("签发失败: %d %s", issued.Code, issued.Body.String())
	}
	ck := gateCookie(t, issued)
	setCookie := issued.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "HttpOnly") || !strings.Contains(setCookie, "SameSite=Strict") || !strings.Contains(setCookie, "Path=/") {
		t.Fatalf("Cookie 属性不完整: %s", setCookie)
	}
	if strings.Contains(setCookie, "Secure") {
		t.Fatalf("明文 HTTP 不得加 Secure: %s", setCookie)
	}
	if ck.MaxAge != 60 {
		t.Fatalf("Max-Age = %d，want 60", ck.MaxAge)
	}
	if strings.Contains(issued.Body.String(), ck.Value) {
		t.Fatal("响应正文不应包含旁路令牌")
	}

	// 回环放行不得消耗一次性令牌。
	loop := gateServe(h, http.MethodGet, "/", "127.0.0.1:9", "", ck)
	if !bytes.Equal(loop.Body.Bytes(), ui.Body.Bytes()) {
		t.Fatal("回环应放行")
	}
	first := gateServe(h, http.MethodGet, "/", remote, "", ck)
	if !bytes.Equal(first.Body.Bytes(), ui.Body.Bytes()) {
		t.Fatalf("首次旁路应放行: %q", first.Body.String())
	}
	second := gateServe(h, http.MethodGet, "/", remote, "", ck)
	if second.Code != http.StatusNotFound || bytes.Equal(second.Body.Bytes(), ui.Body.Bytes()) {
		t.Fatalf("第二次应失效并返回诱饵: %d %q", second.Code, second.Body.String())
	}
	st := g.Stats()
	if st.Bypasses != 1 || st.Decoys != 1 {
		t.Fatalf("一次性计数 = %+v", st)
	}

	g.now = func() time.Time { return base }
	expiredIssued := gateServe(h, http.MethodPost, "/api/gate/bypass", remote, tok)
	expired := gateCookie(t, expiredIssued)
	g.now = func() time.Time { return base.Add(2 * time.Minute) }
	late := gateServe(h, http.MethodGet, "/late", remote, "", expired)
	if late.Code != http.StatusNotFound || bytes.Equal(late.Body.Bytes(), ui.Body.Bytes()) {
		t.Fatalf("过期旁路应返回诱饵: %d %q", late.Code, late.Body.String())
	}

	req := httptest.NewRequest(http.MethodPost, "/api/gate/bypass", strings.NewReader("{}"))
	req.RemoteAddr = remote
	req.Header.Set("Authorization", "Bearer "+tok)
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "Secure") {
		t.Fatalf("HTTPS 应加 Secure: %s", rec.Header().Get("Set-Cookie"))
	}

	stats := gateServe(h, http.MethodGet, "/api/gate/stats", remote, tok)
	if stats.Code != http.StatusOK || !strings.Contains(stats.Body.String(), `"mode":"enforce"`) || !strings.Contains(stats.Body.String(), `"source":"env"`) {
		t.Fatalf("stats = %d %s", stats.Code, stats.Body.String())
	}
}

func TestGateGrantSessionFromOneTime(t *testing.T) {
	const remote = "203.0.113.50:9"
	key := []byte("grant-signing-key")
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	g := newGate(config.GateModeEnforce, config.GateSourceEnv, key, "")
	g.now = func() time.Time { return base }
	g.ttl = time.Minute
	s := &Server{jwtKey: key, gate: g}
	h := s.Handler()
	tok, err := signJWT(key)
	if err != nil {
		t.Fatal(err)
	}
	ui := gateServe(s.webuiHandler(), http.MethodGet, "/", remote, "")
	asset := gateServe(s.webuiHandler(), http.MethodGet, "/assets/app.js", remote, "")

	issued := gateServe(h, http.MethodPost, "/api/gate/bypass", remote, tok)
	if issued.Code != http.StatusOK {
		t.Fatalf("签发失败: %d %s", issued.Code, issued.Body.String())
	}
	one := gateCookie(t, issued)

	first := gateServe(h, http.MethodGet, "/", remote, "", one)
	if first.Code != ui.Code || !bytes.Equal(first.Body.Bytes(), ui.Body.Bytes()) {
		t.Fatalf("首次一次性旁路应放行: %d %q", first.Code, first.Body.String())
	}
	grant := gateNamedCookie(t, first, gateGrantCookie)
	setCookie := first.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, gateGrantCookie+"=") || !strings.Contains(setCookie, "HttpOnly") || !strings.Contains(setCookie, "SameSite=Strict") || !strings.Contains(setCookie, "Path=/") {
		t.Fatalf("授权 Cookie 属性不完整: %s", setCookie)
	}
	if strings.Contains(setCookie, "Secure") {
		t.Fatalf("明文 HTTP 的授权 Cookie 不得加 Secure: %s", setCookie)
	}
	if grant.MaxAge != 60 {
		t.Fatalf("授权 Max-Age = %d，want 60", grant.MaxAge)
	}
	if strings.Contains(first.Body.String(), grant.Value) || strings.Contains(first.Body.String(), one.Value) {
		t.Fatal("响应正文不应包含旁路或授权令牌")
	}
	if st := g.Stats(); st.Bypasses != 1 || st.Decoys != 0 || st.Allows != 1 || st.Hits != 1 {
		t.Fatalf("消费一次性令牌后的计数 = %+v", st)
	}

	// 浏览器还会继续带上尚未过期的一次性 Cookie。授权优先，且不得把已消费的令牌当成失败。
	withBoth := gateServe(h, http.MethodGet, "/assets/app.js", remote, "", one, grant)
	if withBoth.Code != asset.Code || !bytes.Equal(withBoth.Body.Bytes(), asset.Body.Bytes()) {
		t.Fatalf("授权与一次性 Cookie 同时在场应放行静态资源: %d %q", withBoth.Code, withBoth.Body.String())
	}
	home := gateServe(h, http.MethodGet, "/", remote, "", grant)
	if home.Code != ui.Code || !bytes.Equal(home.Body.Bytes(), ui.Body.Bytes()) {
		t.Fatalf("授权 Cookie 第二次应放行: %d %q", home.Code, home.Body.String())
	}
	if st := g.Stats(); st.Bypasses != 1 || st.Allows != 3 || st.Decoys != 0 {
		t.Fatalf("授权复用不得再次计入一次性旁路: %+v", st)
	}

	spent := gateServe(h, http.MethodGet, "/", remote, "", one)
	if spent.Code != http.StatusNotFound || bytes.Equal(spent.Body.Bytes(), ui.Body.Bytes()) {
		t.Fatalf("一次性令牌第二次应失效: %d %q", spent.Code, spent.Body.String())
	}

	tampered := *grant
	tampered.Value = grant.Value[:len(grant.Value)-1]
	if grant.Value[len(grant.Value)-1] == 'a' {
		tampered.Value += "b"
	} else {
		tampered.Value += "a"
	}
	badMac := gateServe(h, http.MethodGet, "/assets/app.js", remote, "", &tampered)
	if badMac.Code != http.StatusNotFound || bytes.Equal(badMac.Body.Bytes(), asset.Body.Bytes()) {
		t.Fatalf("篡改授权应返回诱饵: %d %q", badMac.Code, badMac.Body.String())
	}

	exp, mac, ok := splitGrantToken(grant.Value)
	if !ok {
		t.Fatalf("授权令牌格式不对: %s", grant.Value)
	}
	other := newGate(config.GateModeEnforce, config.GateSourceEnv, []byte("different-grant-key"), "")
	forged := &http.Cookie{Name: gateGrantCookie, Value: exp + "." + other.signGrant(exp)}
	if forged.Value == exp+"."+mac {
		t.Fatal("不同密钥不应签出相同授权")
	}
	foreign := gateServe(h, http.MethodGet, "/", remote, "", forged)
	if foreign.Code != http.StatusNotFound || bytes.Equal(foreign.Body.Bytes(), ui.Body.Bytes()) {
		t.Fatalf("外部构造的授权应返回诱饵: %d %q", foreign.Code, foreign.Body.String())
	}

	g.now = func() time.Time { return base.Add(2 * time.Minute) }
	late := gateServe(h, http.MethodGet, "/assets/app.js", remote, "", grant)
	if late.Code != http.StatusNotFound || bytes.Equal(late.Body.Bytes(), asset.Body.Bytes()) {
		t.Fatalf("过期授权应返回诱饵: %d %q", late.Code, late.Body.String())
	}
	if st := g.Stats(); st.Bypasses != 1 || st.Decoys != 4 {
		t.Fatalf("拒绝伪造授权后的计数 = %+v", st)
	}

	issuedTLS := gateServe(h, http.MethodPost, "/api/gate/bypass", remote, tok)
	oneTLS := gateCookie(t, issuedTLS)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remote
	req.AddCookie(oneTLS)
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != ui.Code || !bytes.Equal(rec.Body.Bytes(), ui.Body.Bytes()) {
		t.Fatalf("HTTPS 上的一次性旁路应放行: %d %q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), gateGrantCookie+"=") || !strings.Contains(rec.Header().Get("Set-Cookie"), "Secure") {
		t.Fatalf("HTTPS 授权 Cookie 应加 Secure: %s", rec.Header().Get("Set-Cookie"))
	}
}

func TestGateOffDetectIgnoreSessionGrant(t *testing.T) {
	const remote = "203.0.113.60:9"
	grant := &http.Cookie{Name: gateGrantCookie, Value: "1.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	one := &http.Cookie{Name: gateBypassCookie, Value: "0123456789abcdef0123456789abcdef.1.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}

	detect := newGate(config.GateModeDetect, config.GateSourceDefault, []byte("detect-grant-key"), "")
	ds := &Server{gate: detect}
	dh := ds.Handler()
	for _, path := range []string{"/", "/assets/app.js"} {
		got := gateServe(dh, http.MethodGet, path, remote, "", grant, one)
		want := gateServe(ds.webuiHandler(), http.MethodGet, path, remote, "")
		if got.Code != want.Code || !bytes.Equal(got.Body.Bytes(), want.Body.Bytes()) || got.Header().Get("Content-Type") != want.Header().Get("Content-Type") {
			t.Fatalf("detect %s 被改写: got %d %q", path, got.Code, got.Body.String())
		}
		if got.Header().Get("Set-Cookie") != "" {
			t.Fatalf("detect 不应下发 Cookie: %s", got.Header().Get("Set-Cookie"))
		}
	}
	if st := detect.Stats(); st.Hits != 2 || st.Allows != 2 || st.Bypasses != 0 || st.Decoys != 0 {
		t.Fatalf("detect 计数 = %+v", st)
	}
	// detect 不消费一次性令牌。切到 enforce 后同一枚令牌仍只能用一次。
	value, _, err := detect.issueBypass()
	if err != nil {
		t.Fatal(err)
	}
	live := &http.Cookie{Name: gateBypassCookie, Value: value}
	seen := gateServe(dh, http.MethodGet, "/", remote, "", live)
	if seen.Header().Get("Set-Cookie") != "" {
		t.Fatalf("detect 见到真令牌也不下发授权: %s", seen.Header().Get("Set-Cookie"))
	}
	detect.mode = config.GateModeEnforce
	ui := gateServe(ds.webuiHandler(), http.MethodGet, "/", remote, "")
	first := gateServe(dh, http.MethodGet, "/", remote, "", live)
	if !bytes.Equal(first.Body.Bytes(), ui.Body.Bytes()) {
		t.Fatalf("detect 期间不应消费令牌: %q", first.Body.String())
	}
	if got := gateNamedCookie(t, first, gateGrantCookie); got.Value == "" {
		t.Fatal("enforce 消费后应下发授权")
	}
	second := gateServe(dh, http.MethodGet, "/", remote, "", live)
	if second.Code != http.StatusNotFound || bytes.Equal(second.Body.Bytes(), ui.Body.Bytes()) {
		t.Fatalf("一次性令牌在 enforce 下第二次应失效: %d %q", second.Code, second.Body.String())
	}

	off := newGate(config.GateModeOff, config.GateSourceEnv, []byte("off-grant-key"), "")
	osrv := &Server{gate: off}
	oh := osrv.Handler()
	got := gateServe(oh, http.MethodGet, "/app", remote, "", grant, one)
	want := gateServe(osrv.webuiHandler(), http.MethodGet, "/app", remote, "")
	if got.Code != want.Code || !bytes.Equal(got.Body.Bytes(), want.Body.Bytes()) || got.Header().Get("Set-Cookie") != "" {
		t.Fatal("off 应与未包门控逐字节一致，且不下发授权")
	}
	if st := off.Stats(); st.Hits != 0 || st.Allows != 0 || st.Bypasses != 0 || st.Decoys != 0 {
		t.Fatalf("off 不应计数: %+v", st)
	}
}

func TestGateOffAndZeroServerUnchanged(t *testing.T) {
	off := newGate(config.GateModeOff, config.GateSourceEnv, []byte("off-key"), "")
	s := &Server{gate: off}
	h := s.Handler()
	got := gateServe(h, http.MethodGet, "/app", "203.0.113.40:9", "")
	want := gateServe(s.webuiHandler(), http.MethodGet, "/app", "203.0.113.40:9", "")
	if got.Code != want.Code || !bytes.Equal(got.Body.Bytes(), want.Body.Bytes()) {
		t.Fatal("off 应与未包门控逐字节一致")
	}
	if st := off.Stats(); st.Hits != 0 || st.Allows != 0 || st.Decoys != 0 {
		t.Fatalf("off 不应计数: %+v", st)
	}

	bare := &Server{}
	bh := bare.Handler()
	bgot := gateServe(bh, http.MethodGet, "/", "203.0.113.41:9", "")
	bwant := gateServe(bare.webuiHandler(), http.MethodGet, "/", "203.0.113.41:9", "")
	if bgot.Code != bwant.Code || !bytes.Equal(bgot.Body.Bytes(), bwant.Body.Bytes()) || bgot.Header().Get("Content-Type") != bwant.Header().Get("Content-Type") {
		t.Fatal("零值 Server 的前端外壳应与原来一致")
	}
	health := gateServe(bh, http.MethodGet, "/api/health", "203.0.113.41:9", "")
	if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), `"service":"artex"`) {
		t.Fatalf("零值 Server 的 /api/health 应保持原样: %d %s", health.Code, health.Body.String())
	}
	stage := gateServe(bh, http.MethodGet, "/s/tok/file", "203.0.113.41:9", "")
	if stage.Body.String() != "404 page not found\n" {
		t.Fatalf("零值 Server 的 stage 路径应保持原样: %q", stage.Body.String())
	}
	key := []byte("zero-server-key")
	bare.jwtKey = key
	tok, err := signJWT(key)
	if err != nil {
		t.Fatal(err)
	}
	// 重新取 Handler，jwtKey 已在第一次 Handler() 之前就该设好。上面的 bh 是旧 mux。
	bare.jwtKey = key
	bh = bare.Handler()
	unknown := gateServe(bh, http.MethodGet, "/api/no-such-gate", "203.0.113.41:9", tok)
	stats := gateServe(bh, http.MethodGet, "/api/gate/stats", "203.0.113.41:9", tok)
	if unknown.Code != stats.Code || unknown.Body.String() != stats.Body.String() {
		t.Fatalf("未初始化时 /api/gate/stats 应与未知 API 一样: unknown=%d %q stats=%d %q", unknown.Code, unknown.Body.String(), stats.Code, stats.Body.String())
	}
}

func TestInitGateDefaultDetect(t *testing.T) {
	t.Setenv("ARTEX_GATE_MODE", "")
	t.Setenv("ARTEX_GATE", "")
	t.Setenv("ARTEX_CONFIG", filepath.Join(t.TempDir(), "missing.json"))
	dir := t.TempDir()
	s := &Server{}
	s.initGate(dir)
	if s.gate == nil || s.gate.mode != config.GateModeDetect || s.gate.source != config.GateSourceDefault {
		t.Fatalf("默认应为 detect/default，got mode=%s source=%s", s.gate.mode, s.gate.source)
	}
	if _, err := os.Stat(filepath.Join(dir, "gate")); err != nil {
		t.Fatal(err)
	}

	t.Setenv("ARTEX_GATE_MODE", "nope")
	s2 := &Server{}
	s2.initGate(t.TempDir())
	if s2.gate.mode != config.GateModeDetect || s2.gate.source != config.GateSourceEnv {
		t.Fatalf("未知 env 应回落 detect 且来源为 env，got mode=%s source=%s", s2.gate.mode, s2.gate.source)
	}

	t.Setenv("ARTEX_GATE_MODE", "off")
	dir3 := t.TempDir()
	s3 := &Server{}
	s3.initGate(dir3)
	if s3.gate.mode != config.GateModeOff || s3.gate.source != config.GateSourceEnv {
		t.Fatalf("off/env got mode=%s source=%s", s3.gate.mode, s3.gate.source)
	}
	if _, err := os.Stat(filepath.Join(dir3, "gate")); !os.IsNotExist(err) {
		t.Fatalf("off 不应创建 data/gate: %v", err)
	}
}

func TestGateStatsFileUsesSharedSnapshot(t *testing.T) {
	dir := t.TempDir()
	when := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	g := newGate(config.GateModeDetect, config.GateSourceDefault, []byte("snap-key"), dir)
	g.now = func() time.Time { return when }
	h := g.WrapUI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	rec := gateServe(h, http.MethodGet, "/x", "198.51.100.2:9", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("detect 应原样返回 204，got %d", rec.Code)
	}
	snap, err := config.ReadGateStats(dir)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Hits != 1 || snap.Allows != 1 || snap.Bypasses != 0 || snap.Decoys != 0 {
		t.Fatalf("快照计数 %+v", snap)
	}
	if snap.Mode != config.GateModeDetect || snap.Source != config.GateSourceDefault {
		t.Fatalf("快照 mode/source %+v", snap)
	}
	if !snap.UpdatedAt.Equal(when) {
		t.Fatalf("快照时间 %s", snap.UpdatedAt)
	}
}

// 节流窗口里的最后一次计数不能永远留在内存：到期要补写，doctor 才能追平。
func TestGateStatsTrailingFlushAfterThrottle(t *testing.T) {
	dir := t.TempDir()
	when := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	g := newGate(config.GateModeDetect, config.GateSourceDefault, []byte("flush-key"), dir)
	g.now = func() time.Time { return when }
	g.persistEvery = 40 * time.Millisecond

	g.hits.Add(1)
	g.persist()
	g.hits.Add(1)
	g.persist() // 窗口内：只安排补偿写

	snap, err := config.ReadGateStats(dir)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Hits != 1 {
		t.Fatalf("节流窗口内不应立即写盘, hits=%d", snap.Hits)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		snap, err = config.ReadGateStats(dir)
		if err == nil && snap.Hits == 2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("补偿写没有追平内存计数, 最后快照 %+v", snap)
}
