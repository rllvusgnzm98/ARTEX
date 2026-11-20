package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/guard"
	"github.com/golang-jwt/jwt/v5"
)

func newTestRing(t *testing.T) (dir string, ring *jwtKeyRing, key []byte) {
	t.Helper()
	t.Setenv("ARTEX_JWT_TTL", "168h")
	t.Setenv("ARTEX_JWT_GRACE", "24h")
	t.Setenv("ARTEX_JWT_ROTATION_PERIOD", "720h")
	dir = t.TempDir()
	key = []byte("0123456789abcdef0123456789abcdef")
	if err := os.WriteFile(filepath.Join(dir, jwtKeyFilename), key, 0o600); err != nil {
		t.Fatal(err)
	}
	ring = loadJWTKeyRing(dir, key)
	if ring == nil || ring.degraded {
		t.Fatal("fresh keyring should load")
	}
	return dir, ring, key
}

func signTestJWT(t *testing.T, key []byte, kid string, method jwt.SigningMethod, exp time.Time) string {
	t.Helper()
	claims := jwt.RegisteredClaims{
		Subject:   "ARTEX",
		ExpiresAt: jwt.NewNumericDate(exp),
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		ID:        "test-jti",
	}
	tok := jwt.NewWithClaims(method, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func keyByKid(t *testing.T, ring *jwtKeyRing, kid string) []byte {
	t.Helper()
	ring.mu.Lock()
	defer ring.mu.Unlock()
	for _, k := range ring.doc.Keys {
		if k.Kid != kid {
			continue
		}
		sec, err := decodeKeySecret(k.Secret)
		if err != nil {
			t.Fatal(err)
		}
		return sec
	}
	t.Fatalf("missing kid %s", kid)
	return nil
}

func TestJWTKeyringLegacyNoKid(t *testing.T) {
	_, ring, key := newTestRing(t)
	legacy, err := signJWT(key)
	if err != nil {
		t.Fatal(err)
	}
	claims, ok := ring.verify(legacy)
	if !ok || claims == nil || claims.Subject != "ARTEX" {
		t.Fatal("无 kid 的旧令牌必须继续用 jwt.key 验签")
	}
	signed, exp, err := ring.sign()
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(exp) < 160*time.Hour {
		t.Fatalf("expiry too soon: %s", exp)
	}
	kid, has := tokenKID(signed)
	if !has || kid != "k1" {
		t.Fatalf("new token kid = %q has=%v", kid, has)
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(signed, &jwt.RegisteredClaims{})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Claims.(*jwt.RegisteredClaims).ID == "" {
		t.Fatal("signed token missing jti")
	}
	if _, ok := ring.verify(signed); !ok {
		t.Fatal("k1 token should verify")
	}
	// 未知 kid 即使用 legacy 密钥签名也拒绝。
	unknown := signTestJWT(t, key, "no-such", jwt.SigningMethodHS256, time.Now().Add(time.Hour))
	if _, ok := ring.verify(unknown); ok {
		t.Fatal("unknown kid must fail closed")
	}
}

func TestJWTKeyringGraceAfterRotation(t *testing.T) {
	dir, ring, _ := newTestRing(t)
	before, err := os.ReadFile(filepath.Join(dir, jwtKeyFilename))
	if err != nil {
		t.Fatal(err)
	}
	oldTok, _, err := ring.sign()
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := ring.rotate(false); err != nil {
		t.Fatal(err)
	}
	after := time.Now()
	gotKey, err := os.ReadFile(filepath.Join(dir, jwtKeyFilename))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, gotKey) {
		t.Fatal("rotation must not modify jwt.key")
	}
	if _, ok := ring.verify(oldTok); !ok {
		t.Fatal("previous key must stay valid during grace")
	}
	ring.mu.Lock()
	var retire time.Time
	for _, k := range ring.doc.Keys {
		if k.Kid == "k1" {
			if k.State != jwtKeyRetiring || k.RetireAt == nil {
				t.Fatalf("k1 state=%s retire=%v", k.State, k.RetireAt)
			}
			retire = *k.RetireAt
		}
	}
	ring.mu.Unlock()
	wantLo := start.Add(192 * time.Hour)
	wantHi := after.Add(192 * time.Hour)
	if retire.Before(wantLo.Add(-time.Second)) || retire.After(wantHi.Add(time.Second)) {
		t.Fatalf("retire_at %s, want about %s..%s", retire, wantLo, wantHi)
	}
	if ring.activeKID() != "k2" {
		t.Fatalf("active=%s", ring.activeKID())
	}

	// TTL+grace 短于 7 天时，窗口抬到 7 天。
	t.Setenv("ARTEX_JWT_TTL", "1h")
	t.Setenv("ARTEX_JWT_GRACE", "1h")
	floorStart := time.Now()
	if err := ring.rotate(false); err != nil {
		t.Fatal(err)
	}
	ring.mu.Lock()
	defer ring.mu.Unlock()
	for _, k := range ring.doc.Keys {
		if k.Kid == "k2" && k.RetireAt != nil && k.RetireAt.Before(floorStart.Add(jwtMinRetireWindow).Add(-time.Second)) {
			t.Fatalf("retire window %s shorter than 7d", k.RetireAt.Sub(floorStart))
		}
	}
}

func TestJWTKeyringRejectsExpiredKey(t *testing.T) {
	_, ring, _ := newTestRing(t)
	tok, _, err := ring.sign()
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.rotate(false); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Minute)
	ring.mu.Lock()
	for i := range ring.doc.Keys {
		if ring.doc.Keys[i].Kid == "k1" {
			ring.doc.Keys[i].RetireAt = &past
		}
	}
	ring.mu.Unlock()
	if _, ok := ring.verify(tok); ok {
		t.Fatal("key past retire_at must be rejected")
	}
	fresh, _, err := ring.sign()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ring.verify(fresh); !ok {
		t.Fatal("active key should still verify")
	}
}

func TestJWTKeyringPrunesAtCap(t *testing.T) {
	_, ring, _ := newTestRing(t)
	for i := 0; i < 3; i++ {
		if err := ring.rotate(false); err != nil {
			t.Fatal(err)
		}
	}
	ring.mu.Lock()
	defer ring.mu.Unlock()
	if len(ring.doc.Keys) != jwtKeyRingMaxKeys {
		t.Fatalf("len=%d want %d", len(ring.doc.Keys), jwtKeyRingMaxKeys)
	}
	for _, k := range ring.doc.Keys {
		if k.Kid == "k1" {
			t.Fatal("earliest retiring key k1 should have been pruned")
		}
	}
	if ring.doc.Active != "k4" {
		t.Fatalf("active=%s", ring.doc.Active)
	}

	// revoked 优先于更早的 retiring。
	ring.doc.Keys[0].State = jwtKeyRevoked
	later := time.Now().Add(48 * time.Hour)
	sooner := time.Now().Add(time.Hour)
	ring.doc.Keys[0].RetireAt = &later
	if ring.doc.Keys[1].State != jwtKeyActive {
		ring.doc.Keys[1].RetireAt = &sooner
	}
	// 人为撑过上限再裁剪。
	ring.doc.Keys = append(ring.doc.Keys, jwtKeyEntry{
		Kid: "k9", Secret: ring.doc.Keys[0].Secret, CreatedAt: time.Now().UTC(), State: jwtKeyRetiring, RetireAt: &sooner,
	})
	revokedKid := ring.doc.Keys[0].Kid
	ring.pruneLocked()
	if len(ring.doc.Keys) != jwtKeyRingMaxKeys {
		t.Fatalf("after prune len=%d", len(ring.doc.Keys))
	}
	for _, k := range ring.doc.Keys {
		if k.Kid == revokedKid {
			t.Fatalf("revoked %s should be dropped before an earlier retiring key", revokedKid)
		}
	}
}

func TestJWTKeyringCorruptFileFailClosed(t *testing.T) {
	dir := t.TempDir()
	key := []byte("0123456789abcdef0123456789abcdef")
	if err := os.WriteFile(filepath.Join(dir, jwtKeyFilename), key, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, jwtKeyRingFilename)
	original := []byte("{not-json\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	ring := loadJWTKeyRing(dir, key)
	if ring == nil || !ring.degraded {
		t.Fatal("corrupt keyring must enter legacy mode")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("corrupt file was overwritten: %q", got)
	}
	legacy, err := signJWT(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ring.verify(legacy); !ok {
		t.Fatal("legacy token must still verify")
	}
	withKid := signTestJWT(t, key, "k1", jwt.SigningMethodHS256, time.Now().Add(time.Hour))
	if _, ok := ring.verify(withKid); ok {
		t.Fatal("unknown kid in legacy mode must be rejected")
	}
	signed, _, err := ring.sign()
	if err != nil {
		t.Fatal(err)
	}
	if _, has := tokenKID(signed); has {
		t.Fatal("legacy mode must sign without kid")
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("sign in legacy mode must not rewrite the corrupt file")
	}
	master, err := os.ReadFile(filepath.Join(dir, jwtKeyFilename))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(master, key) {
		t.Fatal("legacy mode must not rewrite jwt.key")
	}
}

func TestJWTKeyringRejectsNonHS256(t *testing.T) {
	_, ring, key := newTestRing(t)
	exp := time.Now().Add(time.Hour)
	hs384 := signTestJWT(t, key, "k1", jwt.SigningMethodHS384, exp)
	if _, ok := ring.verify(hs384); ok {
		t.Fatal("HS384 must be rejected")
	}
	none := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.RegisteredClaims{
		Subject:   "ARTEX",
		ExpiresAt: jwt.NewNumericDate(exp),
	})
	none.Header["kid"] = "k1"
	noneTok, err := none.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ring.verify(noneTok); ok {
		t.Fatal("alg none must be rejected")
	}
	wrongSub := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   "other",
		ExpiresAt: jwt.NewNumericDate(exp),
	})
	wrongSub.Header["kid"] = "k1"
	bad, err := wrongSub.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ring.verify(bad); ok {
		t.Fatal("sub must be ARTEX")
	}
}

func TestJWTKeyringRotatesWhenAgedAndRevoke(t *testing.T) {
	dir, ring, key := newTestRing(t)
	old, _, err := ring.sign()
	if err != nil {
		t.Fatal(err)
	}
	ring.mu.Lock()
	ring.doc.Keys[0].CreatedAt = time.Now().Add(-1000 * time.Hour)
	ring.mu.Unlock()
	if rotated, err := ring.rotateIfDue(0); err != nil || rotated {
		t.Fatalf("period 0 rotated=%v err=%v", rotated, err)
	}
	if _, ok := ring.verify(old); !ok {
		t.Fatal("disabled rotation must keep the current token")
	}
	rotated, err := ring.rotateIfDue(720 * time.Hour)
	if err != nil || !rotated {
		t.Fatalf("aged key rotated=%v err=%v", rotated, err)
	}
	if _, ok := ring.verify(old); !ok {
		t.Fatal("aged rotation should keep the previous key in grace")
	}

	fresh, _, err := ring.sign()
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.rotate(true); err != nil {
		t.Fatal(err)
	}
	if _, ok := ring.verify(fresh); ok {
		t.Fatal("revoke_previous must reject the previous key immediately")
	}
	master, err := os.ReadFile(filepath.Join(dir, jwtKeyFilename))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(master, key) {
		t.Fatal("revoke must not modify jwt.key")
	}
}

func TestJWTKeyringRegistersLiveFingerprints(t *testing.T) {
	_, ring, key := newTestRing(t)
	if err := ring.rotate(false); err != nil {
		t.Fatal(err)
	}
	k2 := keyByKid(t, ring, "k2")
	s := &Server{jwtKey: key, jwtRing: ring, m: &Manager{egress: guard.NewEgressGuard()}}
	s.registerEgressFingerprints()
	if !fingerprinted(s, key) || !fingerprinted(s, k2) {
		t.Fatal("legacy key and active key must both be fingerprinted")
	}
	if err := ring.rotate(true); err != nil {
		t.Fatal(err)
	}
	s.registerEgressFingerprints()
	if fingerprinted(s, k2) {
		t.Fatal("revoked signing key must be removed from egress fingerprints")
	}
	if !fingerprinted(s, key) {
		t.Fatal("legacy jwt.key must stay fingerprinted")
	}
	k3 := keyByKid(t, ring, ring.activeKID())
	if !fingerprinted(s, k3) {
		t.Fatal("new active key must be fingerprinted")
	}
}

func fingerprinted(s *Server, secret []byte) bool {
	for _, kind := range s.m.egress.CheckKinds(string(secret)) {
		if kind == "jwt_key" {
			return true
		}
	}
	return false
}

func TestJWTKeyringRotateEndpoint(t *testing.T) {
	_, ring, key := newTestRing(t)
	s := &Server{jwtKey: key, jwtRing: ring}
	tok, _, err := ring.sign()
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	unauth := httptest.NewRequest(http.MethodPost, "/api/auth/rotate-key", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, unauth)
	if rec.Code != 401 {
		t.Fatalf("rotate without token: %d", rec.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/auth/rotate-key", strings.NewReader(`{"revoke_previous":false}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		OK     bool   `json:"ok"`
		Active string `json:"active"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.OK || body.Active != "k2" {
		t.Fatalf("body=%s", rec.Body.String())
	}
	if _, ok := ring.verify(tok); !ok {
		t.Fatal("token signed just before manual rotation must survive grace")
	}
	// 确认落盘的 secret 仍是 base64，且 k1 的原文等于 jwt.key。
	raw, err := os.ReadFile(ring.path)
	if err != nil {
		t.Fatal(err)
	}
	var doc jwtKeyRingFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, k := range doc.Keys {
		sec, err := base64.StdEncoding.DecodeString(k.Secret)
		if err != nil || len(sec) == 0 {
			t.Fatalf("kid %s secret not standard base64", k.Kid)
		}
		if k.Kid == "k1" && !bytes.Equal(sec, key) {
			t.Fatal("k1 must remain the legacy jwt.key bytes")
		}
	}
}
