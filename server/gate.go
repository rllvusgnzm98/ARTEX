package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/artex/config"
)

const (
	gateBypassCookie = "artex_bypass"
	gateGrantCookie  = "artex_bypass_grant"
	gateBypassTTL    = 10 * time.Minute
	gateLogWindow    = 30 * time.Second
	gatePersistEvery = 2 * time.Second
	gateMaxLive      = 10000

	// webuiStubNotFound 与 webui_stub.go 的 http.Error 正文一致，只用来对齐诱饵长度。
	// 响应里不会写出这段文字，也不包含产品名。
	webuiStubNotFound = "前端未内嵌到此二进制（开发用 next dev；发布用 -tags embedui 构建）"
)

// decoyMessage 与开发态 webui 404 等长，状态码和 Content-Type 由 http.Error 对齐。
var decoyMessage = buildDecoyMessage()

func buildDecoyMessage() string {
	const base = "404 Not Found. The requested URL is not available on this server."
	buf := make([]byte, len(webuiStubNotFound))
	n := copy(buf, base)
	for i := n; i < len(buf); i++ {
		buf[i] = '.'
	}
	return string(buf)
}

// Gate 是伪装门控。只包前端外壳：off 原样放行，detect 只观测，enforce 在不是
// 本机回环、且没有有效会话授权或一次性旁路时返回诱饵 404。一次性旁路消费后
// 下发可重复使用的会话授权。计数在进程内；data/gate/stats.json 是给 doctor
// 看的快照，不写 activity 表。
type Gate struct {
	mode   string
	source string
	macKey []byte
	ttl    time.Duration

	hits     atomic.Int64
	allows   atomic.Int64
	bypasses atomic.Int64
	decoys   atomic.Int64

	now func() time.Time

	mu   sync.Mutex
	live map[string]int64 // id → unix expiry；用过即删

	logMu   sync.Mutex
	logNext time.Time
	logSkip int

	persistMu    sync.Mutex
	statsPath    string
	persistEvery time.Duration
	lastPersist  time.Time
}

// initGate 在 Server 构造时解析模式。settings 读失败只跳过该层，不把已有的
// env/config 覆盖成别的值；最终无法识别时 ResolveGate 本身回落 detect。
func (s *Server) initGate(dataDir string) {
	var settingsValue string
	var settingsSet bool
	if s.m != nil && s.m.pg != nil {
		v, ok, err := s.m.pg.GetSetting(config.GateModeSettingKey)
		if err != nil {
			log.Printf("[gate] 读取 settings.%s 失败，忽略该层: %v", config.GateModeSettingKey, err)
		} else if ok {
			settingsValue, settingsSet = v, true
		}
	}
	res := config.ResolveGate(settingsValue, settingsSet)
	s.gate = newGate(res.Mode, res.Source, s.jwtKey, dataDir)
	log.Printf("[gate] mode=%s source=%s", s.gate.mode, s.gate.source)
}

func newGate(mode, source string, jwtKey []byte, dataDir string) *Gate {
	g := &Gate{
		mode:         canonicalGateMode(mode),
		source:       source,
		macKey:       deriveGateKey(jwtKey),
		ttl:          gateBypassTTL,
		live:         map[string]int64{},
		persistEvery: gatePersistEvery,
	}
	if g.mode != config.GateModeOff {
		if dir, err := ensureGateDir(dataDir); err != nil {
			log.Printf("[gate] 创建 %s 失败，统计只留在内存: %v", filepath.Join(dataDir, "gate"), err)
		} else if dir != "" {
			g.statsPath = filepath.Join(dir, "stats.json")
		}
	}
	return g
}

func canonicalGateMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case config.GateModeOff, config.GateModeDetect, config.GateModeEnforce:
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return config.GateModeDetect
	}
}

// deriveGateKey 用 jwt.key 做域分离，不另存明文密钥。空密钥返回 nil，签发会失败。
func deriveGateKey(master []byte) []byte {
	if len(master) == 0 {
		return nil
	}
	sum := sha256.Sum256(append([]byte("artex/gate/bypass/v1\x00"), master...))
	out := make([]byte, len(sum))
	copy(out, sum[:])
	return out
}

func ensureGateDir(dataDir string) (string, error) {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return "", nil
	}
	dir := filepath.Join(dataDir, "gate")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func (g *Gate) clock() time.Time {
	if g != nil && g.now != nil {
		return g.now()
	}
	return time.Now()
}

// Stats 是管理接口看到的瞬时计数。
func (g *Gate) Stats() config.GateStatsSnapshot {
	if g == nil {
		return config.GateStatsSnapshot{}
	}
	return config.GateStatsSnapshot{
		Mode:     g.mode,
		Source:   g.source,
		Hits:     g.hits.Load(),
		Allows:   g.allows.Load(),
		Bypasses: g.bypasses.Load(),
		Decoys:   g.decoys.Load(),
	}
}

// WrapUI 只应该包前端外壳。off 直接返回 next，不计数、不打日志。
func (g *Gate) WrapUI(next http.Handler) http.Handler {
	if g == nil || g.mode == config.GateModeOff {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.hits.Add(1)
		switch g.mode {
		case config.GateModeEnforce:
			if isLoopbackRequest(r) {
				g.allows.Add(1)
				g.persist()
				next.ServeHTTP(w, r)
				return
			}
			// 会话授权可重复使用，只计 allows。bypasses 仍只统计一次性令牌的消费。
			if g.acceptGrant(r) {
				g.allows.Add(1)
				g.persist()
				next.ServeHTTP(w, r)
				return
			}
			if g.consumeBypass(r) {
				g.allows.Add(1)
				g.bypasses.Add(1)
				g.persist()
				g.setGrantCookie(w, r)
				next.ServeHTTP(w, r)
				return
			}
			g.decoys.Add(1)
			g.persist()
			g.logLimited("enforce 诱饵 " + r.Method + " " + clipPath(r.URL.Path) + " 来自 " + remoteHost(r))
			writeGateDecoy(w)
		default:
			g.allows.Add(1)
			g.persist()
			g.logLimited("detect 放行 " + r.Method + " " + clipPath(r.URL.Path))
			next.ServeHTTP(w, r)
		}
	})
}

func writeGateDecoy(w http.ResponseWriter) {
	http.Error(w, decoyMessage, http.StatusNotFound)
}

func isLoopbackRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.IsLoopback()
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func clipPath(p string) string {
	if len(p) > 128 {
		return p[:128]
	}
	return p
}

func (g *Gate) logLimited(msg string) {
	now := g.clock()
	g.logMu.Lock()
	skipped := 0
	if now.Before(g.logNext) {
		g.logSkip++
		g.logMu.Unlock()
		return
	}
	skipped = g.logSkip
	g.logSkip = 0
	g.logNext = now.Add(gateLogWindow)
	g.logMu.Unlock()
	if skipped > 0 {
		log.Printf("[gate] %s（另有 %d 条同类已省略）", msg, skipped)
		return
	}
	log.Printf("[gate] %s", msg)
}

// issueBypass 生成一次性旁路。调用方负责鉴权；这里不写日志。
func (g *Gate) issueBypass() (value string, ttl time.Duration, err error) {
	if g == nil || len(g.macKey) == 0 {
		return "", 0, errors.New("旁路密钥不可用")
	}
	ttl = g.ttl
	if ttl <= 0 {
		ttl = gateBypassTTL
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return "", 0, err
	}
	id := hex.EncodeToString(idBytes)
	exp := g.clock().Add(ttl).Unix()
	expStr := strconv.FormatInt(exp, 10)
	mac := g.sign(id, expStr)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepLocked(g.clock().Unix())
	if len(g.live) >= gateMaxLive {
		return "", 0, errors.New("旁路签发过多")
	}
	g.live[id] = exp
	return id + "." + expStr + "." + mac, ttl, nil
}

func (g *Gate) sign(id, exp string) string {
	m := hmac.New(sha256.New, g.macKey)
	_, _ = m.Write([]byte(id))
	_, _ = m.Write([]byte{'.'})
	_, _ = m.Write([]byte(exp))
	return hex.EncodeToString(m.Sum(nil))
}

// signGrant 与一次性令牌分域，避免把旁路串改写成会话授权。
func (g *Gate) signGrant(exp string) string {
	m := hmac.New(sha256.New, g.macKey)
	_, _ = m.Write([]byte("artex/gate/grant/v1\x00"))
	_, _ = m.Write([]byte(exp))
	return hex.EncodeToString(m.Sum(nil))
}

// acceptGrant 认会话授权 Cookie。HMAC 覆盖用途和过期时间，可重复使用；
// 伪造、过期或密钥不可用都拒绝。不写日志，也不消耗一次性旁路。
func (g *Gate) acceptGrant(r *http.Request) bool {
	if g == nil || len(g.macKey) == 0 || r == nil {
		return false
	}
	c, err := r.Cookie(gateGrantCookie)
	if err != nil || c.Value == "" {
		return false
	}
	expStr, mac, ok := splitGrantToken(c.Value)
	if !ok || !hmac.Equal([]byte(mac), []byte(g.signGrant(expStr))) {
		return false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || g.clock().Unix() >= exp {
		return false
	}
	return true
}

// setGrantCookie 在一次性旁路被消费的同一次响应里下发会话授权，TTL 与旁路相同。
// 调用方必须已经消费成功。不写日志。
func (g *Gate) setGrantCookie(w http.ResponseWriter, r *http.Request) {
	if g == nil || len(g.macKey) == 0 || w == nil {
		return
	}
	ttl := g.ttl
	if ttl <= 0 {
		ttl = gateBypassTTL
	}
	expStr := strconv.FormatInt(g.clock().Add(ttl).Unix(), 10)
	secure := r != nil && r.TLS != nil
	http.SetCookie(w, &http.Cookie{
		Name:     gateGrantCookie,
		Value:    expStr + "." + g.signGrant(expStr),
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
	})
}

func splitGrantToken(v string) (exp, mac string, ok bool) {
	exp, mac, ok = strings.Cut(v, ".")
	if !ok || exp == "" || strings.Contains(mac, ".") || len(mac) != 64 {
		return "", "", false
	}
	return exp, mac, true
}

// consumeBypass 校验 Cookie。签名、过期、未使用三者都要通过；成功后立即作废。
func (g *Gate) consumeBypass(r *http.Request) bool {
	if g == nil || len(g.macKey) == 0 || r == nil {
		return false
	}
	c, err := r.Cookie(gateBypassCookie)
	if err != nil || c.Value == "" {
		return false
	}
	id, expStr, mac, ok := splitBypassToken(c.Value)
	if !ok || !hmac.Equal([]byte(mac), []byte(g.sign(id, expStr))) {
		return false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return false
	}
	now := g.clock().Unix()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepLocked(now)
	until, found := g.live[id]
	if !found || until != exp || now >= exp {
		delete(g.live, id)
		return false
	}
	delete(g.live, id)
	return true
}

func splitBypassToken(v string) (id, exp, mac string, ok bool) {
	id, rest, ok1 := strings.Cut(v, ".")
	exp, mac, ok2 := strings.Cut(rest, ".")
	if !ok1 || !ok2 || strings.Contains(mac, ".") {
		return "", "", "", false
	}
	if len(id) != 32 || exp == "" || len(mac) != 64 {
		return "", "", "", false
	}
	return id, exp, mac, true
}

func (g *Gate) sweepLocked(nowUnix int64) {
	for id, exp := range g.live {
		if nowUnix >= exp {
			delete(g.live, id)
		}
	}
}

func (g *Gate) persist() {
	if g == nil || g.statsPath == "" {
		return
	}
	now := g.clock()
	g.persistMu.Lock()
	if g.persistEvery > 0 && !g.lastPersist.IsZero() && now.Sub(g.lastPersist) < g.persistEvery {
		g.persistMu.Unlock()
		return
	}
	g.lastPersist = now
	path := g.statsPath
	snap := config.GateStatsSnapshot{
		Mode:      g.mode,
		Source:    g.source,
		Hits:      g.hits.Load(),
		Allows:    g.allows.Load(),
		Bypasses:  g.bypasses.Load(),
		Decoys:    g.decoys.Load(),
		UpdatedAt: now.UTC(),
	}
	g.persistMu.Unlock()
	if err := writeGateStats(path, snap); err != nil {
		g.logLimited("统计快照写入失败")
	}
}

func writeGateStats(path string, snap config.GateStatsSnapshot) error {
	b, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(path)
		if err2 := os.Rename(tmp, path); err2 != nil {
			_ = os.Remove(tmp)
			return err2
		}
	}
	return nil
}

func (s *Server) gateStats(w http.ResponseWriter, r *http.Request) {
	if s.gate == nil {
		writeErr(w, http.StatusServiceUnavailable, "伪装门控未初始化")
		return
	}
	writeJSON(w, http.StatusOK, s.gate.Stats())
}

func (s *Server) gateBypass(w http.ResponseWriter, r *http.Request) {
	if s.gate == nil {
		writeErr(w, http.StatusServiceUnavailable, "伪装门控未初始化")
		return
	}
	value, ttl, err := s.gate.issueBypass()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "旁路签发失败")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     gateBypassCookie,
		Value:    value,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"ttl_seconds": int(ttl.Seconds()),
		"cookie_name": gateBypassCookie,
	})
}
