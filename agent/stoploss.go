package agent

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

// DefaultSafetyCeiling is the wall-clock cap for a single worker run (20
// minutes, matching the seeded run_seconds=1200). It is a safety ceiling only,
// not the primary "stop when the clock hits 20m" policy. Earlier stop-loss is
// decided by progress signals (no new facts/assets, repeated commands).
const DefaultSafetyCeiling = 20 * time.Minute

// StopLossMessagePrefix marks a harness-enforced stop-loss in the Stop hook
// message. Engine settlement uses it only as a human-readable label; the
// authoritative signal is StopLossVerdict.Fired().
const StopLossMessagePrefix = "【止损】"

// StopLossKind is why a run should stop early, or why the safety ceiling applies.
type StopLossKind string

const (
	StopLossNone            StopLossKind = ""
	StopLossNoProgress      StopLossKind = "no_progress"
	StopLossRepeatedCommand StopLossKind = "repeated_command"
	StopLossSafetyCeiling   StopLossKind = "safety_ceiling"
)

// StopLossPolicy is the harness-side stop policy. Dual insurance: the hook
// enforces this in code. Prompt wording is advisory and is never consulted.
type StopLossPolicy struct {
	// SafetyCeiling is the wall-clock cap, not the primary stop. Zero uses
	// DefaultSafetyCeiling. A negative value disables the cap in Evaluate
	// (the live run still has MaxDuration from run_seconds).
	SafetyCeiling time.Duration
	// IdleProbeLimit is how many probe (non-read, non-write-back) tool calls
	// may run after the last graph write before a no-new-facts/no-new-assets
	// stop fires. Zero uses the default (6).
	IdleProbeLimit int
	// RepeatCommandLimit is how many times the same command fingerprint may
	// appear before a repeated-command stop fires. Zero uses the default (2),
	// so the second identical probe is a repeat.
	RepeatCommandLimit int
}

// DefaultStopLossPolicy returns the product defaults.
func DefaultStopLossPolicy() StopLossPolicy {
	return StopLossPolicy{
		SafetyCeiling:      DefaultSafetyCeiling,
		IdleProbeLimit:     6,
		RepeatCommandLimit: 2,
	}
}

func (p StopLossPolicy) ceiling() time.Duration {
	if p.SafetyCeiling < 0 {
		return 0
	}
	if p.SafetyCeiling == 0 {
		return DefaultSafetyCeiling
	}
	return p.SafetyCeiling
}

func (p StopLossPolicy) idleLimit() int {
	if p.IdleProbeLimit > 0 {
		return p.IdleProbeLimit
	}
	return 6
}

func (p StopLossPolicy) repeatLimit() int {
	if p.RepeatCommandLimit > 0 {
		return p.RepeatCommandLimit
	}
	return 2
}

// ProgressSignals is the observed run progress used by Evaluate.
// Missing-signal flags must stay false when a source cannot be read; Evaluate
// then fail-softs (no hard stop, no target-failure write).
type ProgressSignals struct {
	FactsKnown    bool
	AssetsKnown   bool
	CommandsKnown bool
	NewFacts      int
	NewAssets     int
	NewFindings   int
	IdleProbes    int
	RepeatCount   int
	Elapsed       time.Duration
}

// StopLossVerdict is the policy decision. TargetFailureWrites is always 0:
// stop-loss never records a missing or early stop as a target or goal failure.
type StopLossVerdict struct {
	Kind                StopLossKind
	Detail              string
	TargetFailureWrites int
}

// Fired reports an early stop-loss (not the safety ceiling). The ceiling is
// owned by MaxDuration in a live run; Evaluate still returns it so tests can
// prove the 20-minute value is a cap, not the primary stop.
func (v StopLossVerdict) Fired() bool {
	return v.Kind == StopLossNoProgress || v.Kind == StopLossRepeatedCommand
}

// Message is the Stop-hook / block text when Fired is true.
func (v StopLossVerdict) Message() string {
	if !v.Fired() {
		return ""
	}
	if strings.TrimSpace(v.Detail) == "" {
		return StopLossMessagePrefix + "本轮已无边际进展，提前结束并让出槽位；这不是目标失败，也不等待墙钟上限。"
	}
	return StopLossMessagePrefix + v.Detail
}

// Evaluate applies the stop policy. The safety ceiling is checked last and
// only if no earlier stop-loss fired: a run with progress continues until the
// cap, and a stalled run stops well before 20 minutes.
//
// Missing signals fail-soft: unknown facts/assets do not trigger no-progress
// stop; unknown commands do not trigger a repeat stop. The ceiling still
// applies when elapsed is known. This function never writes goal or target
// state.
func EvaluateStopLoss(p StopLossPolicy, sig ProgressSignals) StopLossVerdict {
	v := StopLossVerdict{}
	if sig.CommandsKnown && sig.RepeatCount >= p.repeatLimit() {
		v.Kind = StopLossRepeatedCommand
		v.Detail = "检测到重复命令，提前止损并让出槽位；这不是目标失败，也不等待墙钟上限。"
		return v
	}
	if sig.FactsKnown && sig.AssetsKnown &&
		sig.NewFacts == 0 && sig.NewAssets == 0 && sig.NewFindings == 0 &&
		sig.IdleProbes >= p.idleLimit() {
		v.Kind = StopLossNoProgress
		v.Detail = "连续探测无新事实也无新资产，提前止损并让出槽位；这不是目标失败，也不等待墙钟上限。"
		return v
	}
	ceiling := p.ceiling()
	if ceiling > 0 && sig.Elapsed >= ceiling {
		v.Kind = StopLossSafetyCeiling
		v.Detail = "已到达单次运行墙钟安全上限。"
		return v
	}
	return v
}

// IntentStateAfterRun maps a finished worker run to an intent state.
// Stop-loss yields the slot as exhausted (partial / no more marginal progress),
// never as a target/goal failure, and never as a successful done.
func IntentStateAfterRun(reason harness.TerminalReason, runErr error, loss StopLossVerdict) string {
	switch {
	case runErr != nil:
		return "blocked"
	case loss.Fired():
		return "exhausted"
	case reason == harness.ReasonMaxTurns || reason == harness.ReasonTimeout:
		return "exhausted"
	default:
		return "done"
	}
}

// StopLossMonitor observes tool use during a run and decides stop-loss.
// It is safe for concurrent hook calls.
type StopLossMonitor struct {
	mu        sync.Mutex
	policy    StopLossPolicy
	started   time.Time
	writes    func() (WriteCounts, bool)
	verdict   StopLossVerdict
	factsOK   bool
	assetsOK  bool
	cmdsOK    bool
	newFacts  int
	newAssets int
	newFinds  int
	idle      int
	repeats   map[string]int
	maxRepeat int
}

// NewStopLossMonitor starts observing from now.
func NewStopLossMonitor(p StopLossPolicy) *StopLossMonitor {
	return &StopLossMonitor{
		policy:   p,
		started:  time.Now(),
		factsOK:  true,
		assetsOK: true,
		cmdsOK:   true,
		repeats:  map[string]int{},
	}
}

// SetWriteSnapshot optionally supplies ToolSet.Writes as a ground-truth
// snapshot. A false ok marks fact/asset signals unknown (fail-soft).
func (m *StopLossMonitor) SetWriteSnapshot(fn func() (WriteCounts, bool)) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.writes = fn
	m.mu.Unlock()
}

// ObserveTool records one completed tool call. Empty tool names and
// un-fingerprintable probe inputs fail-soft for that event.
func (m *StopLossMonitor) ObserveTool(name string, input []byte, isErr bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if strings.TrimSpace(name) == "" {
		// Missing tool identity: do not increment idle or treat as a repeat.
		return
	}
	if isWriteBackTool(name) && !isErr {
		switch name {
		case "record_fact":
			m.newFacts++
			m.idle = 0
		case "insert_assets":
			m.newAssets++
			m.idle = 0
		case "report_finding", "add_finding":
			m.newFinds++
			m.idle = 0
		}
	}
	if isProbeTool(name) {
		fp, ok := commandFingerprint(name, input)
		if !ok {
			// Missing command body: do not invent an idle or repeat signal.
			return
		}
		m.idle++
		m.repeats[fp]++
		if m.repeats[fp] > m.maxRepeat {
			m.maxRepeat = m.repeats[fp]
		}
	}
}

func (m *StopLossMonitor) signalsLocked() ProgressSignals {
	sig := ProgressSignals{
		FactsKnown:    m.factsOK,
		AssetsKnown:   m.assetsOK,
		CommandsKnown: m.cmdsOK,
		NewFacts:      m.newFacts,
		NewAssets:     m.newAssets,
		NewFindings:   m.newFinds,
		IdleProbes:    m.idle,
		RepeatCount:   m.maxRepeat,
		Elapsed:       time.Since(m.started),
	}
	if m.writes != nil {
		w, ok := m.writes()
		if !ok {
			sig.FactsKnown = false
			sig.AssetsKnown = false
		} else {
			sig.NewFacts = w.Facts
			sig.NewAssets = w.Assets
			sig.NewFindings = w.Findings
			sig.FactsKnown = true
			sig.AssetsKnown = true
		}
	}
	return sig
}

// Recompute evaluates current signals and stores the verdict if stop-loss fires.
func (m *StopLossMonitor) Recompute() StopLossVerdict {
	if m == nil {
		return StopLossVerdict{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.recomputeLocked()
}

func (m *StopLossMonitor) recomputeLocked() StopLossVerdict {
	v := EvaluateStopLoss(m.policy, m.signalsLocked())
	// The live hook does not enforce the wall-clock cap (MaxDuration does,
	// and still runs settlement). Only early stop-loss is stored here.
	if v.Fired() {
		m.verdict = v
	}
	return m.verdict
}

// Verdict returns the last fired stop-loss, or a zero verdict.
func (m *StopLossMonitor) Verdict() StopLossVerdict {
	if m == nil {
		return StopLossVerdict{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.verdict
}

// Fired reports whether early stop-loss has already been decided.
func (m *StopLossMonitor) Fired() bool {
	return m.Verdict().Fired()
}

// MarkSignalsUnknown forces fact/asset/command signals into the fail-soft path.
// Used by tests; production code uses missing fingerprints / failed snapshots.
func (m *StopLossMonitor) MarkSignalsUnknown(facts, assets, commands bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if facts {
		m.factsOK = false
	}
	if assets {
		m.assetsOK = false
	}
	if commands {
		m.cmdsOK = false
	}
	m.mu.Unlock()
}

// stopLossHooks wraps an inner HookRunner and enforces stop-loss in the
// harness (PreToolUse blocks further probes; Stop prevents continuation).
type stopLossHooks struct {
	inner harness.HookRunner
	mon   *StopLossMonitor
}

// WrapStopLoss composes stop-loss enforcement with an existing hook runner
// (guard + empty-turn nudges). A nil monitor is a no-op wrapper.
func WrapStopLoss(inner harness.HookRunner, mon *StopLossMonitor) harness.HookRunner {
	if mon == nil {
		return inner
	}
	return stopLossHooks{inner: inner, mon: mon}
}

// AttachStopLossWrites supplies ToolSet.Writes as the ground-truth snapshot
// for fact/asset signals. A false ok fail-softs those signals.
func AttachStopLossWrites(hooks harness.HookRunner, fn func() (WriteCounts, bool)) {
	h, ok := hooks.(stopLossHooks)
	if !ok || h.mon == nil {
		return
	}
	h.mon.SetWriteSnapshot(fn)
}

func (h stopLossHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	if h.mon != nil && h.mon.Fired() && isProbeTool(name) {
		return true, h.mon.Verdict().Message(), nil
	}
	if h.inner != nil {
		return h.inner.PreToolUse(ctx, name, input)
	}
	return false, "", nil
}

func (h stopLossHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	if h.mon != nil {
		h.mon.ObserveTool(name, input, isErr)
		h.mon.Recompute()
	}
	if h.inner != nil {
		h.inner.PostToolUse(ctx, name, input, result, isErr)
	}
}

func (h stopLossHooks) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	if h.mon != nil {
		v := h.mon.Recompute()
		if v.Fired() {
			return true, nil, v.Message()
		}
	}
	if h.inner != nil {
		return h.inner.Stop(ctx, messages)
	}
	return false, nil, ""
}

func isWriteBackTool(name string) bool {
	switch name {
	case "record_fact", "insert_assets", "report_finding", "add_finding":
		return true
	default:
		return false
	}
}

func isProbeTool(name string) bool {
	if name == "" || IsGraphReadTool(name) || isWriteBackTool(name) {
		return false
	}
	switch name {
	case "Bash", "WebFetch", "web_search", "Write", "Edit", "MultiEdit":
		return true
	default:
		// Conservative: unknown tools are not probes, so we do not invent
		// an idle/repeat signal from a name we cannot classify.
		return false
	}
}

func commandFingerprint(name string, input []byte) (string, bool) {
	if !isProbeTool(name) {
		return "", false
	}
	s := strings.TrimSpace(string(input))
	if s == "" {
		return "", false
	}
	var raw map[string]any
	if json.Unmarshal(input, &raw) == nil {
		for _, key := range []string{"command", "cmd", "url", "query"} {
			if v, ok := raw[key].(string); ok && strings.TrimSpace(v) != "" {
				s = strings.TrimSpace(v)
				break
			}
		}
	}
	s = strings.Join(strings.Fields(s), " ")
	if s == "" {
		return "", false
	}
	return name + "\x00" + s, true
}
