package server

// JWT 签名密钥环。jwt.key 同时是 sessions/credentials 的 AES 主密钥和出口指纹，
// 本文件只轮换 keyDir/jwt.keyring.json 里的 HS256 签名密钥，绝不读写 jwt.key。
// 升级前签发的无 kid 令牌永远用 jwt.key 验签，因此可以回滚到旧二进制。

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/config"
	"github.com/golang-jwt/jwt/v5"
)

const (
	jwtKeyRingFilename    = "jwt.keyring.json"
	jwtKeyRingVersion     = 1
	jwtKeyRingMaxKeys     = 3
	jwtRotationCheckEvery = 6 * time.Hour
	jwtClockLeeway        = 60 * time.Second
	jwtMinRetireWindow    = 7 * 24 * time.Hour
	jwtRefreshHeader      = "X-ARTEX-Refresh"

	jwtKeyActive   = "active"
	jwtKeyRetiring = "retiring"
	jwtKeyRevoked  = "revoked"
)

// jwtKeyEntry 是钥匙环里的一把签名密钥。Secret 是原始密钥的标准 base64。
type jwtKeyEntry struct {
	Kid       string     `json:"kid"`
	Secret    string     `json:"secret"`
	CreatedAt time.Time  `json:"created_at"`
	State     string     `json:"state"`
	RetireAt  *time.Time `json:"retire_at,omitempty"`
}

type jwtKeyRingFile struct {
	Version int           `json:"version"`
	Active  string        `json:"active"`
	Keys    []jwtKeyEntry `json:"keys"`
}

// jwtKeyRing 是进程内的签名密钥环。degraded 在装载时确定，之后不再改写：
// 损坏或不可读的文件保持原样，签发/验签退回 jwt.key 且不带 kid。
type jwtKeyRing struct {
	mu       sync.Mutex
	path     string
	legacy   []byte
	doc      jwtKeyRingFile
	degraded bool
	now      func() time.Time
}

func (r *jwtKeyRing) clock() time.Time {
	if r != nil && r.now != nil {
		return r.now()
	}
	return time.Now()
}

// loadJWTKeyRing 打开或创建钥匙环。读失败或内容损坏时不覆盖原文件，退回 legacy 模式。
func loadJWTKeyRing(keyDir string, legacy []byte) *jwtKeyRing {
	r := &jwtKeyRing{
		path:   filepath.Join(keyDir, jwtKeyRingFilename),
		legacy: append([]byte(nil), legacy...),
	}
	data, err := os.ReadFile(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			if len(r.legacy) == 0 {
				log.Printf("[auth] JWT key 为空，keyring 退回 legacy 模式（不创建 %s）", r.path)
				r.degraded = true
				return r
			}
			if err := r.initNew(); err != nil {
				log.Printf("[auth] JWT keyring 创建失败，退回 legacy 模式（不覆盖 %s）: %v", r.path, err)
				r.degraded = true
				r.doc = jwtKeyRingFile{}
			}
			return r
		}
		log.Printf("[auth] JWT keyring 不可读，退回 legacy 模式（不覆盖 %s）: %v", r.path, err)
		r.degraded = true
		return r
	}
	if err := r.parse(data); err != nil {
		log.Printf("[auth] JWT keyring 已损坏，退回 legacy 模式（不覆盖 %s）: %v", r.path, err)
		r.degraded = true
		r.doc = jwtKeyRingFile{}
		return r
	}
	return r
}

func (r *jwtKeyRing) initNew() error {
	now := r.clock().UTC()
	r.doc = jwtKeyRingFile{
		Version: jwtKeyRingVersion,
		Active:  "k1",
		Keys: []jwtKeyEntry{{
			Kid:       "k1",
			Secret:    base64.StdEncoding.EncodeToString(r.legacy),
			CreatedAt: now,
			State:     jwtKeyActive,
		}},
	}
	if err := r.saveLocked(); err != nil {
		return err
	}
	log.Printf("[auth] JWT keyring 已创建 %s active=k1（无 kid 令牌仍用 jwt.key 验签）", r.path)
	return nil
}

func (r *jwtKeyRing) parse(data []byte) error {
	var doc jwtKeyRingFile
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("json: %w", err)
	}
	if doc.Version != jwtKeyRingVersion {
		return fmt.Errorf("version %d", doc.Version)
	}
	if len(doc.Keys) == 0 || len(doc.Keys) > 32 {
		return fmt.Errorf("keys %d", len(doc.Keys))
	}
	doc.Active = strings.TrimSpace(doc.Active)
	seen := map[string]struct{}{}
	activeN := 0
	for i := range doc.Keys {
		k := &doc.Keys[i]
		k.Kid = strings.TrimSpace(k.Kid)
		k.State = strings.TrimSpace(k.State)
		if k.Kid == "" {
			return fmt.Errorf("empty kid")
		}
		if _, ok := seen[k.Kid]; ok {
			return fmt.Errorf("duplicate kid %s", k.Kid)
		}
		seen[k.Kid] = struct{}{}
		if k.CreatedAt.IsZero() {
			return fmt.Errorf("kid %s: created_at 为空", k.Kid)
		}
		switch k.State {
		case jwtKeyActive, jwtKeyRetiring, jwtKeyRevoked:
		default:
			return fmt.Errorf("kid %s: state %q", k.Kid, k.State)
		}
		if _, err := decodeKeySecret(k.Secret); err != nil {
			return fmt.Errorf("kid %s: %w", k.Kid, err)
		}
		if k.State == jwtKeyActive {
			activeN++
		}
	}
	if activeN != 1 {
		return fmt.Errorf("active count %d", activeN)
	}
	if _, ok := seen[doc.Active]; !ok {
		return fmt.Errorf("active %q 不在 keys 里", doc.Active)
	}
	var activeState string
	for _, k := range doc.Keys {
		if k.Kid == doc.Active {
			activeState = k.State
		}
	}
	if activeState != jwtKeyActive {
		return fmt.Errorf("active %s state %s", doc.Active, activeState)
	}
	r.doc = doc
	if len(r.doc.Keys) > jwtKeyRingMaxKeys {
		r.pruneLocked()
		if err := r.saveLocked(); err != nil {
			return err
		}
	}
	return nil
}

func decodeKeySecret(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) > 0 {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(b) > 0 {
		return b, nil
	}
	return nil, fmt.Errorf("secret 无法解码")
}

func (r *jwtKeyRing) saveLocked() error {
	if r.degraded {
		return fmt.Errorf("jwt keyring degraded")
	}
	data, err := json.MarshalIndent(r.doc, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeAtomic0600(r.path, data)
}

// writeAtomic0600 先写同目录临时文件再 rename。Windows 上 rename 不能覆盖已有文件，
// 此时先删目标再改名；临时文件在替换前已经写完。
func writeAtomic0600(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "jwt.keyring-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
			return err
		}
		if err2 := os.Rename(tmp, path); err2 != nil {
			return err2
		}
	}
	cleanup = false
	return os.Chmod(path, 0o600)
}

// sign 用当前 active 键签发，header 带 kid，claims 带 jti。degraded 时退回无 kid 的 jwt.key。
func (r *jwtKeyRing) sign() (string, time.Time, error) {
	if r == nil || r.degraded {
		return signLegacy(nilKey(r))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	active := r.entryLocked(r.doc.Active)
	if active == nil || active.State != jwtKeyActive {
		return signLegacy(r.legacy)
	}
	secret, err := decodeKeySecret(active.Secret)
	if err != nil {
		return "", time.Time{}, err
	}
	now := r.clock().UTC()
	exp := now.Add(currentJWTTTL())
	jti, err := newJTI()
	if err != nil {
		return "", time.Time{}, err
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   "ARTEX",
		ExpiresAt: jwt.NewNumericDate(exp),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        jti,
	})
	t.Header["kid"] = active.Kid
	signed, err := t.SignedString(secret)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, exp, nil
}

func nilKey(r *jwtKeyRing) []byte {
	if r == nil {
		return nil
	}
	return r.legacy
}

func signLegacy(key []byte) (string, time.Time, error) {
	tok, err := signJWT(key)
	if err != nil {
		return "", time.Time{}, err
	}
	return tok, time.Now().Add(currentJWTTTL()), nil
}

func newJTI() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("jti: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// verify 先验签无关地取出 kid。无 kid 走 jwt.key；有 kid 时只接受未过 retire_at 的
// active 或 retiring 键。未知 kid、revoked、非 HS256、sub 不是 ARTEX 一律拒绝。
func (r *jwtKeyRing) verify(tokenStr string) (*jwt.RegisteredClaims, bool) {
	if r == nil {
		return nil, false
	}
	kid, hasKid := tokenKID(tokenStr)
	if !hasKid {
		return verifyHS256(tokenStr, r.legacy)
	}
	if r.degraded {
		return nil, false
	}
	secret, ok := r.secretForKID(kid)
	if !ok {
		return nil, false
	}
	return verifyHS256(tokenStr, secret)
}

func (r *jwtKeyRing) secretForKID(kid string) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock()
	for _, k := range r.doc.Keys {
		if k.Kid != kid {
			continue
		}
		if k.State != jwtKeyActive && k.State != jwtKeyRetiring {
			return nil, false
		}
		if k.RetireAt != nil && !now.Before(*k.RetireAt) {
			return nil, false
		}
		sec, err := decodeKeySecret(k.Secret)
		if err != nil {
			return nil, false
		}
		return sec, true
	}
	return nil, false
}

// tokenKID 不做信任决策，只读 header。kid 存在但不是非空字符串时 hasKid 仍为真，
// 调用方按未知 kid 拒绝，避免退回 legacy 键。
func tokenKID(tokenStr string) (kid string, hasKid bool) {
	if strings.TrimSpace(tokenStr) == "" {
		return "", false
	}
	t, _, err := jwt.NewParser().ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil || t == nil {
		return "", false
	}
	v, ok := t.Header["kid"]
	if !ok || v == nil {
		return "", false
	}
	s, ok := v.(string)
	if !ok {
		return "", true
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	return s, true
}

func verifyHS256(tokenStr string, key []byte) (*jwt.RegisteredClaims, bool) {
	if tokenStr == "" || len(key) == 0 {
		return nil, false
	}
	claims := &jwt.RegisteredClaims{}
	t, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		return key, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithLeeway(jwtClockLeeway),
		jwt.WithSubject("ARTEX"),
	)
	if err != nil || t == nil || !t.Valid {
		return nil, false
	}
	return claims, true
}

// rotate 生成下一把 active 键。上一把默认进入 retiring，retire_at = now+TTL+grace
// 且不短于 7 天；revokePrevious 为真时上一把立即 revoked。超过 3 把时裁剪。
func (r *jwtKeyRing) rotate(revokePrevious bool) error {
	if r == nil || r.degraded {
		return fmt.Errorf("jwt keyring unavailable")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rotateLocked(revokePrevious)
}

func (r *jwtKeyRing) rotateLocked(revokePrevious bool) error {
	prevID := r.doc.Active
	prevIdx := -1
	for i := range r.doc.Keys {
		if r.doc.Keys[i].Kid == prevID {
			prevIdx = i
			break
		}
	}
	if prevIdx < 0 {
		return fmt.Errorf("no active key")
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("generate jwt signing key: %w", err)
	}
	now := r.clock().UTC()
	retireAt := jwtRetireAt(now)
	next := r.doc
	next.Keys = append([]jwtKeyEntry(nil), r.doc.Keys...)
	if revokePrevious {
		revokedAt := now
		next.Keys[prevIdx].State = jwtKeyRevoked
		next.Keys[prevIdx].RetireAt = &revokedAt
	} else {
		next.Keys[prevIdx].State = jwtKeyRetiring
		next.Keys[prevIdx].RetireAt = &retireAt
	}
	kid := nextKID(next.Keys)
	next.Keys = append(next.Keys, jwtKeyEntry{
		Kid:       kid,
		Secret:    base64.StdEncoding.EncodeToString(secret),
		CreatedAt: now,
		State:     jwtKeyActive,
	})
	next.Active = kid
	saved := r.doc
	r.doc = next
	r.pruneLocked()
	if err := r.saveLocked(); err != nil {
		r.doc = saved
		return err
	}
	log.Printf("[auth] JWT 签名密钥已轮换 active=%s previous=%s revoke=%t", kid, prevID, revokePrevious)
	return nil
}

// rotateIfDue 在 active 键龄达到周期时轮换。period <= 0 表示关闭。
func (r *jwtKeyRing) rotateIfDue(period time.Duration) (bool, error) {
	if r == nil || r.degraded || period <= 0 {
		return false, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	active := r.entryLocked(r.doc.Active)
	if active == nil {
		return false, fmt.Errorf("no active key")
	}
	if r.clock().Sub(active.CreatedAt) < period {
		return false, nil
	}
	if err := r.rotateLocked(false); err != nil {
		return false, err
	}
	return true, nil
}

func (r *jwtKeyRing) entryLocked(kid string) *jwtKeyEntry {
	for i := range r.doc.Keys {
		if r.doc.Keys[i].Kid == kid {
			return &r.doc.Keys[i]
		}
	}
	return nil
}

func nextKID(keys []jwtKeyEntry) string {
	maxN := 0
	for _, k := range keys {
		var n int
		if _, err := fmt.Sscanf(k.Kid, "k%d", &n); err == nil && n > maxN {
			maxN = n
		}
	}
	return fmt.Sprintf("k%d", maxN+1)
}

// jwtRetireAt 让例行轮换不断仍在寿命内的会话：窗口是 TTL+grace，且至少 7 天。
func jwtRetireAt(now time.Time) time.Time {
	window := currentJWTTTL() + config.JWTGrace()
	if window < jwtMinRetireWindow {
		window = jwtMinRetireWindow
	}
	return now.Add(window)
}

// pruneLocked 超过上限时优先丢掉 revoked，其次丢掉 retire_at 最早的非 active 键。
func (r *jwtKeyRing) pruneLocked() {
	for len(r.doc.Keys) > jwtKeyRingMaxKeys {
		idx := r.dropIndexLocked()
		if idx < 0 {
			return
		}
		r.doc.Keys = append(r.doc.Keys[:idx], r.doc.Keys[idx+1:]...)
	}
}

func (r *jwtKeyRing) dropIndexLocked() int {
	best := -1
	bestRank := 2
	var bestTime time.Time
	for i, k := range r.doc.Keys {
		if k.Kid == r.doc.Active || k.State == jwtKeyActive {
			continue
		}
		rank := 1
		if k.State == jwtKeyRevoked {
			rank = 0
		}
		t := time.Time{}
		if k.RetireAt != nil {
			t = k.RetireAt.UTC()
		}
		if best < 0 || rank < bestRank || (rank == bestRank && t.Before(bestTime)) {
			best = i
			bestRank = rank
			bestTime = t
		}
	}
	return best
}

func (r *jwtKeyRing) activeKID() string {
	if r == nil || r.degraded {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.doc.Active
}

// liveSecrets 返回仍可用于验签的密钥原文（active / 未过期 retiring）。不含 revoked。
// legacy 的 jwt.key 由调用方单独登记，无 kid 令牌始终靠它验签。
func (r *jwtKeyRing) liveSecrets() [][]byte {
	if r == nil || r.degraded {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock()
	var out [][]byte
	for _, k := range r.doc.Keys {
		if k.State != jwtKeyActive && k.State != jwtKeyRetiring {
			continue
		}
		if k.RetireAt != nil && !now.Before(*k.RetireAt) {
			continue
		}
		sec, err := decodeKeySecret(k.Secret)
		if err != nil {
			continue
		}
		out = append(out, sec)
	}
	return out
}

// bootJWTKeyRing 装载钥匙环，按键龄轮换一次，并启动可随 ctx 停止的 6 小时检查。
func (s *Server) bootJWTKeyRing(keyDir string) {
	if s == nil {
		return
	}
	s.jwtRing = loadJWTKeyRing(keyDir, s.jwtKey)
	if s.jwtRing == nil || s.jwtRing.degraded {
		return
	}
	rotated, err := s.jwtRing.rotateIfDue(config.JWTRotationPeriod())
	if err != nil {
		log.Printf("[auth] JWT 启动轮换失败: %v", err)
	} else if rotated {
		log.Printf("[auth] JWT 签名密钥已按龄轮换 active=%s", s.jwtRing.activeKID())
	}
	s.startJWTRotationLoop()
}

func (s *Server) startJWTRotationLoop() {
	if s == nil || s.jwtRing == nil || s.jwtRing.degraded || s.ctx == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(jwtRotationCheckEvery)
		defer ticker.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				rotated, err := s.jwtRing.rotateIfDue(config.JWTRotationPeriod())
				if err != nil {
					log.Printf("[auth] JWT 定时轮换失败: %v", err)
					continue
				}
				if rotated {
					log.Printf("[auth] JWT 签名密钥已按周期轮换 active=%s", s.jwtRing.activeKID())
					s.registerEgressFingerprints()
				}
			}
		}
	}()
}
