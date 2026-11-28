// Package oob provides an ARTEX-managed Out-of-Band (OOB) callback collector
// for blind XSS, SSRF, XXE, RCE, and async victim/admin-bot verification.
//
// Two drivers are supported:
//   - "http" (default): built-in HTTP callback receiver mounted at /o/<token>[/...],
//     persisted to disk with bounded retention and instant long-poll wakeup.
//   - "interactsh": optional managed interactsh-client sidecar for DNS/SMTP/HTTP
//     callbacks when interactsh-client is installed on the host/container.
package oob

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	DefaultTTL = 2 * time.Hour
	MaxTTL     = 24 * time.Hour
	minTTL     = time.Minute
	gcInterval = time.Minute

	maxEventsPerEntry    = 200
	maxBodyBytes         = 16384
	maxHeaderBytes       = 4096
	maxResponseBodyBytes = 4096
	maxWaitDuration      = 30 * time.Second
	defaultPollLimit     = 50

	tokenRateLimit  = 120
	ipRateLimit     = 300
	rateLimitWindow = time.Minute

	DriverHTTP       = "http"
	DriverInteractsh = "interactsh"

	EventAllocate = "allocate"
	EventHit      = "hit"
	EventExpire   = "expire"
	EventDestroy  = "destroy"
)

var (
	ErrNotFound      = errors.New("oob endpoint not found or expired")
	ErrInvalidDriver = errors.New("unsupported oob driver (must be http or interactsh)")
)

type AllocateOpts struct {
	TaskID       string
	Label        string
	TTL          time.Duration
	Driver       string
	StatusCode   int
	ContentType  string
	ResponseBody string
}

type Entry struct {
	Token        string    `json:"token"`
	TaskID       string    `json:"task_id,omitempty"`
	Label        string    `json:"label,omitempty"`
	Driver       string    `json:"driver"`
	Path         string    `json:"path"`
	URL          string    `json:"url"`
	PayloadHost  string    `json:"payload_host,omitempty"`
	StatusCode   int       `json:"status_code"`
	ContentType  string    `json:"content_type"`
	ResponseBody string    `json:"response_body,omitempty"`
	Hits         int64     `json:"hits"`
	NextSeq      int64     `json:"next_seq"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type Interaction struct {
	Seq           int64             `json:"seq"`
	Timestamp     time.Time         `json:"timestamp"`
	Protocol      string            `json:"protocol"`
	Method        string            `json:"method,omitempty"`
	Path          string            `json:"path,omitempty"`
	Query         string            `json:"query,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	Body          string            `json:"body,omitempty"`
	BodyTruncated bool              `json:"body_truncated,omitempty"`
	RemoteIP      string            `json:"remote_ip,omitempty"`
	ContentType   string            `json:"content_type,omitempty"`
	Raw           string            `json:"raw,omitempty"`
}

type Event struct {
	Kind        string
	Entry       Entry
	Interaction *Interaction
}

type liveEntry struct {
	entry    Entry
	events   []Interaction
	notifyCh chan struct{}
	cancel   context.CancelFunc
}

type Manager struct {
	dir     string
	dataDir string

	mu      sync.Mutex
	entries map[string]*liveEntry
	baseURL string

	OnEvent func(Event)

	rateMu   sync.Mutex
	tokenHit map[string][]time.Time
	ipHit    map[string][]time.Time

	stopGC context.CancelFunc
}

// New creates a persistent OOB callback manager storing metadata and events under dir.
// Unexpired HTTP entries on disk are reloaded across restarts.
func New(ctx context.Context, dir string) (*Manager, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("oob dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("oob dir chmod: %w", err)
	}
	m := &Manager{
		dir:      dir,
		dataDir:  filepath.Dir(dir),
		entries:  map[string]*liveEntry{},
		tokenHit: map[string][]time.Time{},
		ipHit:    map[string][]time.Time{},
	}
	m.loadFromDisk(time.Now())
	gcCtx, cancel := context.WithCancel(ctx)
	m.stopGC = cancel
	go m.gcLoop(gcCtx)
	return m, nil
}

// Close stops background GC and any active sidecar processes without erasing
// unexpired persisted entries.
func (m *Manager) Close() {
	if m.stopGC != nil {
		m.stopGC()
	}
	m.mu.Lock()
	var cancels []context.CancelFunc
	for _, le := range m.entries {
		if le.cancel != nil {
			cancels = append(cancels, le.cancel)
			le.cancel = nil
		}
	}
	m.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}

// SetBaseURL configures the external base URL (e.g. http://10.0.0.2:8787)
// prepended to /o/<token> URLs.
func (m *Manager) SetBaseURL(u string) {
	m.mu.Lock()
	m.baseURL = strings.TrimRight(strings.TrimSpace(u), "/")
	for _, le := range m.entries {
		if le.entry.Driver == DriverHTTP {
			le.entry.URL = m.httpURLForLocked(le.entry.Token)
		}
	}
	m.mu.Unlock()
}

// BaseURL returns the configured external base URL for HTTP OOB endpoints.
func (m *Manager) BaseURL() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.baseURL
}

func (m *Manager) httpURLForLocked(token string) string {
	p := "/o/" + token
	if m.baseURL == "" {
		return p
	}
	return m.baseURL + p
}

// Allocate creates a new OOB callback endpoint scoped to opts.TaskID.
func (m *Manager) Allocate(opts AllocateOpts) (*Entry, error) {
	driver := strings.ToLower(strings.TrimSpace(opts.Driver))
	if driver == "" {
		driver = DriverHTTP
	}
	if driver != DriverHTTP && driver != DriverInteractsh {
		return nil, ErrInvalidDriver
	}

	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if ttl < minTTL {
		ttl = minTTL
	}
	if ttl > MaxTTL {
		ttl = MaxTTL
	}

	statusCode := opts.StatusCode
	if statusCode < 100 || statusCode > 599 {
		statusCode = http.StatusOK
	}
	ct := strings.TrimSpace(opts.ContentType)
	if ct == "" {
		ct = "text/plain; charset=utf-8"
	}
	respBody := opts.ResponseBody
	if respBody == "" {
		respBody = "ok"
	}
	if len(respBody) > maxResponseBodyBytes {
		respBody = respBody[:maxResponseBodyBytes]
	}

	token, err := newToken()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	e := Entry{
		Token:        token,
		TaskID:       strings.TrimSpace(opts.TaskID),
		Label:        strings.TrimSpace(opts.Label),
		Driver:       driver,
		Path:         "/o/" + token,
		StatusCode:   statusCode,
		ContentType:  ct,
		ResponseBody: respBody,
		CreatedAt:    now,
		ExpiresAt:    now.Add(ttl),
	}

	le := &liveEntry{
		entry:    e,
		notifyCh: make(chan struct{}),
	}

	if driver == DriverHTTP {
		m.mu.Lock()
		le.entry.URL = m.httpURLForLocked(token)
		m.entries[token] = le
		snap := le.entry
		m.mu.Unlock()
		_ = m.saveMeta(snap)
		m.emit(Event{Kind: EventAllocate, Entry: snap})
		return &snap, nil
	}

	// interactsh driver
	binPath, err := m.findInteractshBinary()
	if err != nil {
		return nil, err
	}
	procCtx, procCancel := context.WithCancel(context.Background())
	payloadHost, err := m.startInteractsh(procCtx, procCancel, binPath, le)
	if err != nil {
		procCancel()
		return nil, err
	}
	le.cancel = procCancel
	le.entry.PayloadHost = payloadHost
	le.entry.URL = "http://" + payloadHost

	m.mu.Lock()
	m.entries[token] = le
	snap := le.entry
	m.mu.Unlock()
	_ = m.saveMeta(snap)
	m.emit(Event{Kind: EventAllocate, Entry: snap})
	return &snap, nil
}

// HandleHTTP serves and records an HTTP callback targeting /o/{token}[/{rest...}].
func (m *Manager) HandleHTTP(w http.ResponseWriter, r *http.Request, token, subpath string) {
	ip := remoteIP(r)
	if !m.allowAttempt(token, ip) {
		notFound(w)
		return
	}

	m.mu.Lock()
	le, ok := m.entries[token]
	if !ok || le.entry.Driver != DriverHTTP || time.Now().After(le.entry.ExpiresAt) {
		m.mu.Unlock()
		notFound(w)
		return
	}
	statusCode := le.entry.StatusCode
	ct := le.entry.ContentType
	respBody := le.entry.ResponseBody
	m.mu.Unlock()

	var bodyStr string
	var truncated bool
	if r.Body != nil {
		limited := io.LimitReader(r.Body, maxBodyBytes+1)
		raw, _ := io.ReadAll(limited)
		if len(raw) > maxBodyBytes {
			raw = raw[:maxBodyBytes]
			truncated = true
		}
		bodyStr = string(raw)
	}

	headers := map[string]string{}
	headerBytes := 0
	for k, vals := range r.Header {
		val := strings.Join(vals, ", ")
		entryLen := len(k) + len(val) + 2
		if headerBytes+entryLen > maxHeaderBytes {
			break
		}
		headers[k] = val
		headerBytes += entryLen
	}

	reqPath := r.URL.Path
	if subpath != "" && !strings.HasPrefix(subpath, "/") {
		subpath = "/" + subpath
	}
	ev := Interaction{
		Timestamp:     time.Now().UTC(),
		Protocol:      "http",
		Method:        r.Method,
		Path:          reqPath,
		Query:         r.URL.RawQuery,
		Headers:       headers,
		Body:          bodyStr,
		BodyTruncated: truncated,
		RemoteIP:      ip,
		ContentType:   r.Header.Get("Content-Type"),
	}
	m.recordInteraction(token, ev)

	// Permissive CORS so browser-based XSS/CSRF probes succeed regardless of origin.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Max-Age", "600")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(statusCode)
	_, _ = io.WriteString(w, respBody)
}

func (m *Manager) recordInteraction(token string, ev Interaction) {
	m.mu.Lock()
	le, ok := m.entries[token]
	if !ok || time.Now().After(le.entry.ExpiresAt) {
		m.mu.Unlock()
		return
	}
	le.entry.NextSeq++
	le.entry.Hits++
	ev.Seq = le.entry.NextSeq
	le.events = append(le.events, ev)
	if len(le.events) > maxEventsPerEntry {
		le.events = le.events[len(le.events)-maxEventsPerEntry:]
	}
	close(le.notifyCh)
	le.notifyCh = make(chan struct{})
	snapEntry := le.entry
	snapEv := ev
	m.mu.Unlock()

	_ = m.appendEventDisk(token, snapEv)
	_ = m.saveMeta(snapEntry)
	m.emit(Event{Kind: EventHit, Entry: snapEntry, Interaction: &snapEv})
}

// Poll returns interactions with Seq > sinceSeq for token (scoped to taskID if non-empty).
// If none exist and wait > 0, it blocks up to min(wait, maxWaitDuration) for a new hit.
func (m *Manager) Poll(ctx context.Context, taskID, token string, sinceSeq int64, wait time.Duration, limit int) ([]Interaction, *Entry, error) {
	if limit <= 0 || limit > maxEventsPerEntry {
		limit = defaultPollLimit
	}
	if wait < 0 {
		wait = 0
	}
	if wait > maxWaitDuration {
		wait = maxWaitDuration
	}

	var timer *time.Timer
	var timerCh <-chan time.Time
	if wait > 0 {
		timer = time.NewTimer(wait)
		defer timer.Stop()
		timerCh = timer.C
	}

	for {
		m.mu.Lock()
		le, ok := m.entries[token]
		if !ok || time.Now().After(le.entry.ExpiresAt) {
			m.mu.Unlock()
			return nil, nil, ErrNotFound
		}
		if taskID != "" && le.entry.TaskID != taskID {
			m.mu.Unlock()
			return nil, nil, ErrNotFound
		}
		var out []Interaction
		for _, ev := range le.events {
			if ev.Seq > sinceSeq {
				out = append(out, ev)
				if len(out) >= limit {
					break
				}
			}
		}
		snap := le.entry
		ch := le.notifyCh
		m.mu.Unlock()

		if len(out) > 0 || wait == 0 {
			return out, &snap, nil
		}

		select {
		case <-ctx.Done():
			return nil, &snap, ctx.Err()
		case <-timerCh:
			// Return empty list cleanly on wait timeout.
			return []Interaction{}, &snap, nil
		case <-ch:
			// New interaction arrived; loop and collect.
		}
	}
}

// List returns active entries (filtered by taskID if non-empty), newest first.
func (m *Manager) List(taskID string) []Entry {
	now := time.Now()
	taskID = strings.TrimSpace(taskID)
	m.mu.Lock()
	out := make([]Entry, 0, len(m.entries))
	for _, le := range m.entries {
		if now.After(le.entry.ExpiresAt) {
			continue
		}
		if taskID != "" && le.entry.TaskID != taskID {
			continue
		}
		out = append(out, le.entry)
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out
}

// Delete removes an OOB endpoint (enforcing taskID match when taskID is non-empty).
func (m *Manager) Delete(taskID, token string) bool {
	taskID = strings.TrimSpace(taskID)
	m.mu.Lock()
	le, ok := m.entries[token]
	if ok && taskID != "" && le.entry.TaskID != taskID {
		m.mu.Unlock()
		return false
	}
	m.mu.Unlock()
	return m.remove(token, EventDestroy) != nil
}

func (m *Manager) remove(token, kind string) *Entry {
	m.mu.Lock()
	le, ok := m.entries[token]
	if ok {
		delete(m.entries, token)
	}
	m.mu.Unlock()
	if !ok {
		return nil
	}
	if le.cancel != nil {
		le.cancel()
	}
	_ = os.Remove(filepath.Join(m.dir, token+".meta.json"))
	_ = os.Remove(filepath.Join(m.dir, token+".events.jsonl"))
	snap := le.entry
	m.emit(Event{Kind: kind, Entry: snap})
	return &snap
}

func (m *Manager) gcLoop(ctx context.Context) {
	t := time.NewTicker(gcInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			m.sweep(now)
		}
	}
}

func (m *Manager) sweep(now time.Time) {
	m.mu.Lock()
	var expired []string
	for token, le := range m.entries {
		if now.After(le.entry.ExpiresAt) {
			expired = append(expired, token)
		}
	}
	m.mu.Unlock()
	for _, token := range expired {
		m.remove(token, EventExpire)
	}
}

func (m *Manager) saveMeta(e Entry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	tmp := filepath.Join(m.dir, e.Token+".meta.json.tmp")
	dst := filepath.Join(m.dir, e.Token+".meta.json")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func (m *Manager) appendEventDisk(token string, ev Interaction) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(m.dir, token+".events.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}

func (m *Manager) loadFromDisk(now time.Time) {
	items, err := os.ReadDir(m.dir)
	if err != nil {
		return
	}
	for _, it := range items {
		name := it.Name()
		if !strings.HasSuffix(name, ".meta.json") {
			continue
		}
		token := strings.TrimSuffix(name, ".meta.json")
		raw, err := os.ReadFile(filepath.Join(m.dir, name))
		if err != nil {
			continue
		}
		var e Entry
		if json.Unmarshal(raw, &e) != nil || e.Token == "" {
			continue
		}
		if now.After(e.ExpiresAt) {
			_ = os.Remove(filepath.Join(m.dir, token+".meta.json"))
			_ = os.Remove(filepath.Join(m.dir, token+".events.jsonl"))
			continue
		}
		events := m.loadEventsDisk(token)
		if len(events) > maxEventsPerEntry {
			events = events[len(events)-maxEventsPerEntry:]
		}
		m.entries[token] = &liveEntry{
			entry:    e,
			events:   events,
			notifyCh: make(chan struct{}),
		}
	}
}

func (m *Manager) loadEventsDisk(token string) []Interaction {
	f, err := os.Open(filepath.Join(m.dir, token+".events.jsonl"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []Interaction
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), maxBodyBytes*2)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev Interaction
		if json.Unmarshal([]byte(line), &ev) == nil {
			out = append(out, ev)
		}
	}
	return out
}

func (m *Manager) allowAttempt(token, ip string) bool {
	now := time.Now()
	cutoff := now.Add(-rateLimitWindow)
	m.rateMu.Lock()
	defer m.rateMu.Unlock()
	if len(m.tokenHit) > 4096 {
		m.tokenHit = map[string][]time.Time{}
	}
	if len(m.ipHit) > 4096 {
		m.ipHit = map[string][]time.Time{}
	}
	th := append(prune(m.tokenHit[token], cutoff), now)
	m.tokenHit[token] = th
	ih := append(prune(m.ipHit[ip], cutoff), now)
	m.ipHit[ip] = ih
	return len(th) <= tokenRateLimit && len(ih) <= ipRateLimit
}

func prune(ts []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(ts) && ts[i].Before(cutoff) {
		i++
	}
	return ts[i:]
}

func (m *Manager) emit(ev Event) {
	if m.OnEvent != nil {
		m.OnEvent(ev)
	}
}

func newToken() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("oob token: %w", err)
	}
	return "o_" + hex.EncodeToString(buf), nil
}

func notFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(w, "404 page not found\n")
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

var reInteractshHost = regexp.MustCompile(`([a-z0-9]{10,}\.[a-z0-9.-]+\.[a-z]{2,})`)

func (m *Manager) findInteractshBinary() (string, error) {
	if p := strings.TrimSpace(os.Getenv("ARTEX_INTERACTSH_PATH")); p != "" {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
		return "", fmt.Errorf("ARTEX_INTERACTSH_PATH=%q not found", p)
	}
	local := filepath.Join(m.dataDir, "tools", "interactsh-client")
	if st, err := os.Stat(local); err == nil && !st.IsDir() {
		return local, nil
	}
	if p, err := exec.LookPath("interactsh-client"); err == nil {
		return p, nil
	}
	return "", errors.New("interactsh-client binary not installed (use driver=\"http\" or install interactsh-client)")
}

func (m *Manager) startInteractsh(ctx context.Context, cancel context.CancelFunc, binPath string, le *liveEntry) (string, error) {
	args := []string{"-json", "-v", "-poll-interval", "2"}
	if srv := strings.TrimSpace(os.Getenv("ARTEX_INTERACTSH_SERVER")); srv != "" {
		args = append(args, "-server", srv)
	}
	cmd := exec.CommandContext(ctx, binPath, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start interactsh-client: %w", err)
	}

	hostCh := make(chan string, 1)
	errCh := make(chan error, 1)
	scanStream := func(r io.Reader) {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 4096), maxBodyBytes*2)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			// Detect JSON interaction event
			if strings.HasPrefix(line, "{") {
				var raw map[string]any
				if json.Unmarshal([]byte(line), &raw) == nil {
					if _, hasProto := raw["protocol"]; hasProto {
						ev := Interaction{
							Timestamp: time.Now().UTC(),
							Protocol:  fmt.Sprint(raw["protocol"]),
							RemoteIP:  fmt.Sprint(raw["remote-address"]),
							Raw:       line,
						}
						if req, ok := raw["raw-request"].(string); ok {
							if len(req) > maxBodyBytes {
								req = req[:maxBodyBytes]
								ev.BodyTruncated = true
							}
							ev.Body = req
						}
						m.recordInteraction(le.entry.Token, ev)
						continue
					}
				}
			}
			if mHost := reInteractshHost.FindStringSubmatch(line); len(mHost) > 1 {
				select {
				case hostCh <- mHost[1]:
				default:
				}
			}
		}
	}

	go scanStream(stdout)
	go scanStream(stderr)
	go func() {
		werr := cmd.Wait()
		select {
		case errCh <- werr:
		default:
		}
	}()

	select {
	case host := <-hostCh:
		return host, nil
	case werr := <-errCh:
		cancel()
		if werr != nil {
			return "", fmt.Errorf("interactsh-client exited: %w", werr)
		}
		return "", errors.New("interactsh-client exited before assigning domain")
	case <-time.After(10 * time.Second):
		cancel()
		return "", errors.New("timed out waiting for interactsh-client domain")
	}
}
