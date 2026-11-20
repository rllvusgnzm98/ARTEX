package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWTRefreshValidToken(t *testing.T) {
	_, ring, key := newTestRing(t)
	s := &Server{jwtKey: key, jwtRing: ring}
	legacy, err := signJWT(key)
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+legacy)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("refresh legacy: %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Token == "" || body.Token == legacy {
		t.Fatalf("expected a new token, got %q", body.Token)
	}
	if body.ExpiresAt < time.Now().Add(160*time.Hour).Unix() {
		t.Fatalf("expires_at %d too soon", body.ExpiresAt)
	}
	kid, has := tokenKID(body.Token)
	if !has || kid != ring.activeKID() {
		t.Fatalf("refreshed kid=%q has=%v active=%s", kid, has, ring.activeKID())
	}
	if _, ok := s.authenticate(body.Token); !ok {
		t.Fatal("refreshed token should verify")
	}

	// retiring 键上的客户端刷新后升到 active。
	if err := ring.rotate(false); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+body.Token)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("refresh retiring: %d %s", rec.Code, rec.Body.String())
	}
	var upgraded struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &upgraded); err != nil {
		t.Fatal(err)
	}
	kid, has = tokenKID(upgraded.Token)
	if !has || kid != ring.activeKID() || kid == "k1" {
		t.Fatalf("upgraded kid=%q active=%s", kid, ring.activeKID())
	}
}

func TestJWTRefreshRejectsExpiredAndForged(t *testing.T) {
	_, ring, key := newTestRing(t)
	s := &Server{jwtKey: key, jwtRing: ring}
	h := s.Handler()
	call := func(tok string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", strings.NewReader(""))
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := call(""); code != 401 {
		t.Fatalf("missing token: %d", code)
	}
	expired := signTestJWT(t, key, "k1", jwt.SigningMethodHS256, time.Now().Add(-2*time.Minute))
	if code := call(expired); code != 401 {
		t.Fatalf("expired: %d", code)
	}
	forged := signTestJWT(t, []byte("another-signing-key-32-bytes-long"), "k1", jwt.SigningMethodHS256, time.Now().Add(time.Hour))
	if code := call(forged); code != 401 {
		t.Fatalf("forged: %d", code)
	}
	garbage := "not-a-token"
	if code := call(garbage); code != 401 {
		t.Fatalf("garbage: %d", code)
	}
}

func TestJWTRefreshHeaderNearExpiry(t *testing.T) {
	_, ring, key := newTestRing(t)
	s := &Server{jwtKey: key, jwtRing: ring}
	h := s.Handler()

	preflight := httptest.NewRequest(http.MethodOptions, "/api/auth/refresh", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, preflight)
	if got := rec.Header().Get("Access-Control-Expose-Headers"); got != jwtRefreshHeader {
		t.Fatalf("expose headers = %q", got)
	}

	fresh, _, err := ring.sign()
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+fresh)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("fresh refresh: %d %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get(jwtRefreshHeader); got != "" {
		t.Fatalf("fresh token should not ask for refresh, got %q", got)
	}

	near := signTestJWT(t, key, "k1", jwt.SigningMethodHS256, time.Now().Add(time.Hour))
	req = httptest.NewRequest(http.MethodGet, "/api/health", nil)
	// health 不走鉴权，用 requireAuth 包一层普通处理来观察响应头。
	protected := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req = httptest.NewRequest(http.MethodGet, "/api/tasks", nil)
	req.Header.Set("Authorization", "Bearer "+near)
	rec = httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != 204 {
		t.Fatalf("near-expiry request: %d %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get(jwtRefreshHeader); got != "1" {
		t.Fatalf("near-expiry header = %q", got)
	}

	// 剩余寿命不低于 TTL/3 时不发头。168h/3 = 56h。
	comfortable := signTestJWT(t, key, "k1", jwt.SigningMethodHS256, time.Now().Add(60*time.Hour))
	req = httptest.NewRequest(http.MethodGet, "/api/tasks", nil)
	req.Header.Set("Authorization", "Bearer "+comfortable)
	rec = httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	if rec.Code != 204 {
		t.Fatalf("comfortable request: %d", rec.Code)
	}
	if got := rec.Header().Get(jwtRefreshHeader); got != "" {
		t.Fatalf("comfortable header = %q", got)
	}

	// 刷新接口对即将过期的令牌同样带上头。
	req = httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+near)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("near refresh: %d %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get(jwtRefreshHeader); got != "1" {
		t.Fatalf("refresh near-expiry header = %q", got)
	}
}
