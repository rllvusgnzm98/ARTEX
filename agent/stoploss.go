package agent

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
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

const (
	defaultIdleProbeLimit     = 8
	defaultRepeatCommandLimit = 3
)

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
	// IdleProbeLimit is how many target-facing probe tool calls may run after
	// the last graph write before a no-new-facts/no-new-assets stop fires.
	// Zero uses the default (8, overridable via ARTEX_STOPLOSS_IDLE_PROBES).
	IdleProbeLimit int
	// RepeatCommandLimit is how many times the same command fingerprint may
	// appear within the current idle window before a repeated-command stop fires.
	// Zero uses the default (3, overridable via ARTEX_STOPLOSS_REPEAT_LIMIT).
	RepeatCommandLimit int
}

func envPositiveInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	if n, err := strconv.Atoi(raw); err == nil && n > 0 {
		return n
	}
	return fallback
}

// DefaultStopLossPolicy returns the product defaults, honoring optional
// ARTEX_STOPLOSS_IDLE_PROBES and ARTEX_STOPLOSS_REPEAT_LIMIT env overrides so
// operators can calibrate thresholds and capture effective values in provenance.
func DefaultStopLossPolicy() StopLossPolicy {
	return StopLossPolicy{
		SafetyCeiling:      DefaultSafetyCeiling,
		IdleProbeLimit:     envPositiveInt("ARTEX_STOPLOSS_IDLE_PROBES", defaultIdleProbeLimit),
		RepeatCommandLimit: envPositiveInt("ARTEX_STOPLOSS_REPEAT_LIMIT", defaultRepeatCommandLimit),
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
	return defaultIdleProbeLimit
}

func (p StopLossPolicy) repeatLimit() int {
	if p.RepeatCommandLimit > 0 {
		return p.RepeatCommandLimit
	}
	return defaultRepeatCommandLimit
}

// ProgressSignals is the observed run progress used by Evaluate.
// NewFacts, NewAssets, and NewFindings are writes in the current idle
// window (since the last successful write, or the start of the run), not
// whole-run totals. Missing-signal flags must stay false when a source
// cannot be read; Evaluate then fail-softs (no hard stop, no target-failure write).
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
	Signals             ProgressSignals
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
// No-progress is judged against the idle window: IdleProbes counts consecutive
// probes since the last successful write, and New* counts only writes in that
// same window. A successful write resets the window; whole-run cumulative
// New*==0 is not a gate. Missing signals fail-soft: unknown facts/assets do
// not trigger no-progress stop; unknown commands do not trigger a repeat stop.
// The ceiling still applies when elapsed is known. This function never writes
// goal or target state.
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
	case isRunBudgetError(runErr):
		return "exhausted"
	case IsCallTimeout(runErr):
		return "open" // 墙钟超时 ≠ 目标失败,也不标 blocked;用户取消不走这条
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
	mu             sync.Mutex
	policy         StopLossPolicy
	started        time.Time
	writes         func() (WriteCounts, bool)
	writeBaseline  WriteCounts
	baselineSet    bool
	verdict        StopLossVerdict
	factsOK        bool
	assetsOK       bool
	cmdsOK         bool
	newFacts       int
	newAssets      int
	newFinds       int
	idle           int
	inFlightProbes int
	repeats        map[string]int
	maxRepeat      int
	preWriteNudged bool
	turnSeq        int64
	nudgedTurn     int64
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

// BeginModelTurn marks the start of a new LLM completion turn so same-turn
// multi-tool write-back reminders can hold back remaining probes in that turn
// while still letting the next turn proceed normally if the worker chooses not
// to write back. Also resets inFlightProbes as a safety net for interrupted tools.
func (m *StopLossMonitor) BeginModelTurn() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.turnSeq++
	m.inFlightProbes = 0
	m.mu.Unlock()
}

func (m *StopLossMonitor) noteProbeStarted() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.inFlightProbes++
	m.mu.Unlock()
}

// SetWriteSnapshot optionally supplies ToolSet.Writes as a ground-truth
// snapshot. A false ok marks fact/asset signals unknown (fail-soft).
// The first readable snapshot becomes the idle-window baseline so later
// Evaluate calls use a delta since the last successful write, not whole-run
// totals.
func (m *StopLossMonitor) SetWriteSnapshot(fn func() (WriteCounts, bool)) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writes = fn
	if fn == nil {
		return
	}
	if w, ok := fn(); ok {
		m.writeBaseline = w
		m.baselineSet = true
	}
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
	if isCountableIdleProbe(name, input) && m.inFlightProbes > 0 {
		m.inFlightProbes--
	}
	// A snapshot increase is a successful write even if the tool name is
	// not one we classify as write-back. Catch it before counting this
	// event so the new idle window starts cleanly.
	m.noteSnapshotWritesLocked()
	if isWriteBackTool(name) && !isErr {
		// Start a new idle window. Do not carry whole-run New* into it:
		// no-progress is "idleProbeLimit consecutive probes with no new
		// write since the last successful one", not "the run never wrote".
		m.resetIdleWindowLocked()
	}
	if isProbeTool(name) {
		fp, ok := commandFingerprint(name, input)
		if !ok {
			// Missing command body: do not invent an idle or repeat signal.
			return
		}
		if isCountableIdleProbe(name, input) {
			m.idle++
		}
		m.repeats[fp]++
		if m.repeats[fp] > m.maxRepeat {
			m.maxRepeat = m.repeats[fp]
		}
		// A genuinely new local file edit (Write/Edit/MultiEdit) mutates scripts or
		// payloads in the workspace, so re-running e.g. `python3 exploit.py` via Bash
		// is not repeating an unchanged probe. Clear prior Bash repeat counts while
		// preserving identical Write/Edit loop detection.
		if isLocalEditTool(name) && !isErr && m.repeats[fp] == 1 {
			m.clearBashRepeatsLocked()
		}
	}
}

func (m *StopLossMonitor) clearBashRepeatsLocked() {
	m.maxRepeat = 0
	for k, c := range m.repeats {
		if strings.HasPrefix(k, "Bash\x00") {
			delete(m.repeats, k)
			continue
		}
		if c > m.maxRepeat {
			m.maxRepeat = c
		}
	}
}

// resetIdleWindowLocked starts a new idle window after a successful write.
func (m *StopLossMonitor) resetIdleWindowLocked() {
	m.idle = 0
	m.newFacts = 0
	m.newAssets = 0
	m.newFinds = 0
	m.preWriteNudged = false
	m.nudgedTurn = 0
	m.repeats = map[string]int{}
	m.maxRepeat = 0
	if m.writes == nil {
		return
	}
	if w, ok := m.writes(); ok {
		m.writeBaseline = w
		m.baselineSet = true
	}
}

// noteSnapshotWritesLocked folds ToolSet.Writes into the current window.
// The first readable snapshot is only a baseline (pre-existing totals are
// not "new"). A later increase is treated as a successful write and resets
// the idle window.
func (m *StopLossMonitor) noteSnapshotWritesLocked() {
	if m.writes == nil {
		return
	}
	w, ok := m.writes()
	if !ok {
		return
	}
	if !m.baselineSet {
		m.writeBaseline = w
		m.baselineSet = true
		return
	}
	if w.Facts > m.writeBaseline.Facts ||
		w.Assets > m.writeBaseline.Assets ||
		w.Findings > m.writeBaseline.Findings {
		m.resetIdleWindowLocked()
	}
}

func writeDelta(current, baseline int) int {
	if current < baseline {
		return 0
	}
	return current - baseline
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
			if !m.baselineSet {
				m.writeBaseline = w
				m.baselineSet = true
			}
			// Delta since the last successful write, not whole-run totals.
			sig.NewFacts = writeDelta(w.Facts, m.writeBaseline.Facts)
			sig.NewAssets = writeDelta(w.Assets, m.writeBaseline.Assets)
			sig.NewFindings = writeDelta(w.Findings, m.writeBaseline.Findings)
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
	if m.verdict.Fired() {
		return m.verdict
	}
	signals := m.signalsLocked()
	v := EvaluateStopLoss(m.policy, signals)
	// The live hook does not enforce the wall-clock cap (MaxDuration does,
	// and still runs settlement). Only early stop-loss is stored here.
	if v.Fired() {
		v.Signals = signals
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

// StopLossWriteBackReminderPrefix marks the pre-latch write-back reminder in a
// PreToolUse block message. It is NOT a stop-loss: the run continues, the idle
// counter and the verdict are untouched, and the policy thresholds are unchanged.
// The reminder only gives the worker a chance to persist what it already
// observed before the idle window runs out, so a run that made real progress
// records it instead of losing it to the latch.
const StopLossWriteBackReminderPrefix = "【写回提醒】"

const writeBackReminderBody = "你已连续多次探测但还没有把结果写回知识图谱（写进图才算进展，脑子/文字里的不算）。" +
	"本次工具调用【未执行】：若你已经观察到可写回的内容，请现在就逐条写回——新资产用 insert_assets、探索结论/事实用 record_fact、确认漏洞用 report_finding，" +
	"只写你本次【真实观察到】的，不要为了凑进展编造或把已有事实换措辞重记。" +
	"若确实没有新发现，无需写回，直接继续你的下一步探测即可（连续无进展仍会按原策略止损，这不是目标失败）。"

const sameTurnWriteBackHoldBody = "本回合已发出写回提醒，同回合剩余探测已暂停执行，避免在你看到提醒前直接触发止损。请先处理上面的写回提醒（如有已观察到的新资产/事实/漏洞请先写回），再继续下一步探测。"

const stopLossPostBlockWriteHint = "（仍可在本轮收尾内调用 record_fact / insert_assets / report_finding 把已真实观察到的事实、资产或漏洞写回图谱，之后结束返回。）"

// RemindWriteBack decides whether to interrupt a probe once, before the
// no_progress latch, so the worker can persist observations it has already
// made. It fires at most once per idle window (holding back additional probes
// emitted in the SAME model turn so they cannot latch before the model sees the
// reminder), only for a target-facing probe tool, only while the run is not
// latched, and only when the idle window (including concurrent in-flight probes)
// is one probe away from the no_progress limit with no new write in that window.
func (m *StopLossMonitor) RemindWriteBack(name string) (string, bool) {
	return m.remindWriteBackFor(name, nil)
}

func (m *StopLossMonitor) remindWriteBackFor(name string, input []byte) (string, bool) {
	if m == nil {
		return "", false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.verdict.Fired() {
		return "", false
	}
	if !isCountableIdleProbe(name, input) {
		return "", false
	}
	if m.preWriteNudged {
		if m.turnSeq > 0 && m.nudgedTurn == m.turnSeq {
			return StopLossWriteBackReminderPrefix + sameTurnWriteBackHoldBody, true
		}
		return "", false
	}
	sig := m.signalsLocked()
	// Only when no_progress is genuinely approaching and progress is readable.
	// Missing signals fail-soft exactly like the latch itself.
	if !sig.FactsKnown || !sig.AssetsKnown {
		return "", false
	}
	if sig.NewFacts != 0 || sig.NewAssets != 0 || sig.NewFindings != 0 {
		return "", false
	}
	threshold := m.policy.idleLimit() - 1
	if threshold < 1 {
		threshold = 1
	}
	if sig.IdleProbes+m.inFlightProbes < threshold {
		return "", false
	}
	m.preWriteNudged = true
	m.nudgedTurn = m.turnSeq
	return StopLossWriteBackReminderPrefix + writeBackReminderBody, true
}

// SteerPender is implemented by an inner HookRunner that can hold a queued
// operator course-correction. The write-back reminder yields to it, so the
// correction is delivered on this call instead of being shadowed.
type SteerPender interface {
	SteerPending() bool
}

func steerPending(inner harness.HookRunner) bool {
	p, ok := inner.(SteerPender)
	return ok && p.SteerPending()
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
// for fact/asset signals. Counts are applied as a delta against the last
// successful write (or the snapshot at attach time), not as whole-run totals.
// A false ok fail-softs those signals.
func AttachStopLossWrites(hooks harness.HookRunner, fn func() (WriteCounts, bool)) {
	h, ok := hooks.(stopLossHooks)
	if !ok || h.mon == nil {
		return
	}
	h.mon.SetWriteSnapshot(fn)
}

func (h stopLossHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	if verdict := h.mon.Verdict(); verdict.Fired() {
		if !isWriteBackTool(name) {
			return true, verdict.Message() + stopLossPostBlockWriteHint, nil
		}
	} else if !steerPending(h.inner) {
		if msg, ok := h.mon.remindWriteBackFor(name, input); ok {
			return true, msg, nil
		}
	}
	if h.inner != nil {
		block, msg, updated := h.inner.PreToolUse(ctx, name, input)
		if block {
			return true, msg, updated
		}
		if len(updated) > 0 {
			input = updated
		}
		if isCountableIdleProbe(name, input) {
			h.mon.noteProbeStarted()
		}
		return false, msg, updated
	}
	if isCountableIdleProbe(name, input) {
		h.mon.noteProbeStarted()
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

func isLocalEditTool(name string) bool {
	switch name {
	case "Write", "Edit", "MultiEdit":
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

// isCountableIdleProbe reports whether a tool call should consume the
// no_progress idle probe budget. Local workspace edits (Write/Edit/MultiEdit)
// and provably local read-only Bash inspections (e.g. cat/grep/ls on spill
// output) are preparation/parsing, not target-facing probes.
func isCountableIdleProbe(name string, input []byte) bool {
	if !isProbeTool(name) || isLocalEditTool(name) {
		return false
	}
	if name == "Bash" && len(input) > 0 {
		var raw struct {
			Command string `json:"command"`
		}
		if json.Unmarshal(input, &raw) == nil && isLocalReadOnlyBash(raw.Command) {
			return false
		}
	}
	return true
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
