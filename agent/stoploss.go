package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math/bits"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
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
	defaultIdleProbeLimit     = 14
	defaultRepeatCommandLimit = 4
	defaultMaxNovelRelief     = 16
	maxMilestoneIdleBonus     = 18
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
	// IdleProbeLimit is how many non-novel target-facing probe tool calls may
	// run after the last graph write before a no_progress stop fires.
	// Zero uses the default (14, overridable via ARTEX_STOPLOSS_IDLE_PROBES).
	IdleProbeLimit int
	// RepeatCommandLimit is how many times the same command fingerprint may
	// appear within the current idle window before a repeated-command stop fires.
	// Zero uses the default (4, overridable via ARTEX_STOPLOSS_REPEAT_LIMIT).
	RepeatCommandLimit int
	// MaxNovelRelief bounds how many probes with genuinely distinct output
	// signatures in the current idle window are exempted from advancing IdleProbes.
	// Zero uses the default (16, overridable via ARTEX_STOPLOSS_NOVEL_RELIEF);
	// negative disables output-novelty relief.
	MaxNovelRelief int
	// WriteBackReminder enables the optional PreToolUse blocking reminder one
	// probe before IdleProbeLimit. Disabled by default so workers do not spam
	// fragmented intermediate facts; overridable via ARTEX_STOPLOSS_WRITE_REMINDER.
	WriteBackReminder bool
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

func envBoolFlag(key string, fallback bool) bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

// DefaultStopLossPolicy returns the product defaults, honoring optional
// ARTEX_STOPLOSS_IDLE_PROBES, ARTEX_STOPLOSS_REPEAT_LIMIT,
// ARTEX_STOPLOSS_NOVEL_RELIEF, and ARTEX_STOPLOSS_WRITE_REMINDER env overrides
// so operators can calibrate thresholds and capture effective values in provenance.
func DefaultStopLossPolicy() StopLossPolicy {
	return StopLossPolicy{
		SafetyCeiling:      DefaultSafetyCeiling,
		IdleProbeLimit:     envPositiveInt("ARTEX_STOPLOSS_IDLE_PROBES", defaultIdleProbeLimit),
		RepeatCommandLimit: envPositiveInt("ARTEX_STOPLOSS_REPEAT_LIMIT", defaultRepeatCommandLimit),
		MaxNovelRelief:     envPositiveInt("ARTEX_STOPLOSS_NOVEL_RELIEF", defaultMaxNovelRelief),
		WriteBackReminder:  envBoolFlag("ARTEX_STOPLOSS_WRITE_REMINDER", false),
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

func (p StopLossPolicy) novelLimit() int {
	if p.MaxNovelRelief < 0 {
		return 0
	}
	if p.MaxNovelRelief == 0 {
		return defaultMaxNovelRelief
	}
	return p.MaxNovelRelief
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
	seenObs        map[string]int
	novelCount     int
	milestoneBonus int
	preWriteNudged bool
	cleanupUsed    bool
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
		seenObs:  map[string]int{},
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

// ObserveTool records one completed tool call without its output payload.
// Callers with tool output available should call ObserveToolResult so genuine
// response differentials do not prematurely count as stagnation.
func (m *StopLossMonitor) ObserveTool(name string, input []byte, isErr bool) {
	m.ObserveToolResult(name, input, nil, isErr)
}

// ObserveToolResult records one completed tool call alongside its result output.
// Empty tool names and un-fingerprintable probe inputs fail-soft for that event.
func (m *StopLossMonitor) ObserveToolResult(name string, input, result []byte, isErr bool) {
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
		if name == "report_finding" {
			m.milestoneBonus += 6
			if m.milestoneBonus > maxMilestoneIdleBonus {
				m.milestoneBonus = maxMilestoneIdleBonus
			}
		}
		// Start a new idle window. Do not carry whole-run New* into it:
		// no-progress is "idleProbeLimit consecutive non-novel probes with no
		// new write since the last successful one", not "the run never wrote".
		m.resetIdleWindowLocked()
	}
	if isProbeTool(name) {
		fp, ok := commandFingerprint(name, input)
		if !ok {
			// Missing command body: do not invent an idle or repeat signal.
			return
		}
		if isCountableIdleProbe(name, input) {
			sig := observationSignature(result, isErr)
			novelCap := m.policy.novelLimit()
			switch {
			case sig == "" || novelCap <= 0 || len(m.seenObs) == 0:
				if sig != "" {
					m.seenObs[sig]++
				}
				m.idle++
			case m.seenObs[sig] == 0 && m.novelCount < novelCap:
				m.seenObs[sig] = 1
				m.novelCount++
			default:
				m.seenObs[sig]++
				m.idle++
			}
		}
		m.repeats[fp]++
		if m.repeats[fp] > m.maxRepeat {
			m.maxRepeat = m.repeats[fp]
		}
		// A genuinely new local file edit (Write/Edit/MultiEdit or local heredoc
		// script creation) mutates scripts/payloads in the workspace, so re-running
		// e.g. `python3 exploit.py` via Bash is not repeating an unchanged probe.
		if (isLocalEditTool(name) || isLocalWorkspaceWriteBashTool(name, input)) && !isErr && m.repeats[fp] == 1 {
			m.clearBashRepeatsLocked(fp)
		}
	}
}

func (m *StopLossMonitor) clearBashRepeatsLocked(exceptFP string) {
	m.maxRepeat = 0
	for k, c := range m.repeats {
		if strings.HasPrefix(k, "Bash\x00") && k != exceptFP {
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
	m.cleanupUsed = false
	m.nudgedTurn = 0
	m.repeats = map[string]int{}
	m.maxRepeat = 0
	m.seenObs = map[string]int{}
	m.novelCount = 0
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

// Signals returns the current live progress counters.
func (m *StopLossMonitor) Signals() ProgressSignals {
	if m == nil {
		return ProgressSignals{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.signalsLocked()
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
	eff := m.policy
	if m.milestoneBonus > 0 {
		eff.IdleProbeLimit = eff.idleLimit() + m.milestoneBonus
	}
	v := EvaluateStopLoss(eff, signals)
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

const stopLossPostBlockWriteHint = "（仍可在本轮收尾内调用 record_fact / insert_assets / report_finding 把已真实观察到的事实、资产或漏洞写回图谱，若已启动靶机容器也可发一次 /close 请求释放槽位，之后结束返回。）"

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
	if m == nil || !m.policy.WriteBackReminder {
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
	threshold := m.policy.idleLimit() + m.milestoneBonus - 1
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

func (m *StopLossMonitor) allowPostLatchCleanup(name string, input []byte) bool {
	if m == nil || name != "Bash" || len(input) == 0 {
		return false
	}
	var raw struct {
		Command string `json:"command"`
	}
	if json.Unmarshal(input, &raw) != nil || !isPostLatchCleanupBash(raw.Command) {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cleanupUsed {
		return false
	}
	m.cleanupUsed = true
	return true
}

// isPostLatchCleanupBash allows a single standalone curl POST/DELETE call to a
// container/session teardown endpoint (/close, /stop, /release, /terminate,
// /destroy) after stop-loss latches so leased benchmark slots do not leak.
func isPostLatchCleanupBash(command string) bool {
	words, ok := tokenizeCleanupCurl(command)
	if !ok || len(words) < 2 || strings.Contains(words[0], "=") {
		return false
	}
	if filepath.Base(words[0]) != "curl" {
		return false
	}
	hasMethod := false
	var urls []string
	var expect string // "method" | "url" | "skip"
	for _, w := range words[1:] {
		switch expect {
		case "method":
			m := strings.ToUpper(w)
			if m == "POST" || m == "DELETE" {
				hasMethod = true
			}
			expect = ""
			continue
		case "url":
			urls = append(urls, w)
			expect = ""
			continue
		case "skip":
			expect = ""
			continue
		}
		if strings.HasPrefix(w, "-") {
			switch {
			case w == "-X" || w == "--request":
				expect = "method"
			case strings.HasPrefix(w, "-X") && len(w) > 2:
				m := strings.ToUpper(w[2:])
				if m == "POST" || m == "DELETE" {
					hasMethod = true
				}
			case strings.HasPrefix(w, "--request="):
				m := strings.ToUpper(strings.TrimPrefix(w, "--request="))
				if m == "POST" || m == "DELETE" {
					hasMethod = true
				}
			case w == "--url":
				expect = "url"
			case strings.HasPrefix(w, "--url="):
				urls = append(urls, strings.TrimPrefix(w, "--url="))
			case cleanupCurlValueFlags[w]:
				expect = "skip"
			}
			continue
		}
		urls = append(urls, w)
	}
	if !hasMethod || expect != "" || len(urls) != 1 {
		return false
	}
	u, err := url.Parse(urls[0])
	if err != nil || u.Hostname() == "" {
		return false
	}
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return false
	}
	p := strings.TrimRight(strings.ToLower(u.Path), "/")
	for _, suffix := range []string{"/close", "/stop", "/release", "/terminate", "/destroy"} {
		if strings.HasSuffix(p, suffix) {
			return true
		}
	}
	return false
}

var cleanupCurlValueFlags = map[string]bool{
	"-H": true, "--header": true, "-A": true, "--user-agent": true,
	"-m": true, "--max-time": true, "--connect-timeout": true,
	"-d": true, "--data": true, "--data-raw": true, "--data-binary": true,
	"--data-urlencode": true, "--json": true, "-F": true, "--form": true,
	"-u": true, "--user": true, "-b": true, "--cookie": true,
	"-c": true, "--cookie-jar": true, "-x": true, "--proxy": true,
	"--cacert": true, "--cert": true, "--key": true,
	"-o": true, "--output": true, "-w": true, "--write-out": true,
	"-D": true, "--dump-header": true, "-e": true, "--referer": true,
}

func tokenizeCleanupCurl(command string) ([]string, bool) {
	if strings.TrimSpace(command) == "" {
		return nil, false
	}
	var words []string
	var cur strings.Builder
	var quote byte
	active := false
	flush := func() {
		if active {
			words = append(words, cur.String())
			cur.Reset()
			active = false
		}
	}
	for i := 0; i < len(command); i++ {
		c := command[i]
		if c == 0 || c == '\n' || c == '\r' {
			return nil, false
		}
		if quote == '\'' {
			if c == '\'' {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
			continue
		}
		if c == '\\' {
			if i+1 == len(command) {
				return nil, false
			}
			i++
			cur.WriteByte(command[i])
			active = true
			continue
		}
		if quote == '"' {
			switch c {
			case '"':
				quote = 0
			case '`':
				return nil, false
			case '$':
				if i+1 < len(command) && (command[i+1] == '(' || command[i+1] == '{') {
					return nil, false
				}
				cur.WriteByte(c)
			default:
				cur.WriteByte(c)
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			active = true
		case ' ', '\t':
			flush()
		case '|', '&', ';', '<', '>', '`', '(', ')', '{', '}', '$':
			return nil, false
		default:
			cur.WriteByte(c)
			active = true
		}
	}
	if quote != 0 {
		return nil, false
	}
	flush()
	return words, true
}

func (h stopLossHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	if verdict := h.mon.Verdict(); verdict.Fired() {
		if !isWriteBackTool(name) && !h.mon.allowPostLatchCleanup(name, input) {
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
		h.mon.ObserveToolResult(name, input, result, isErr)
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
// no_progress idle probe budget. Local workspace edits (Write/Edit/MultiEdit,
// or local heredoc script writes via Bash) and provably local read-only Bash
// inspections (e.g. cat/grep/ls on spill output) are preparation/parsing, not
// target-facing probes.
func isCountableIdleProbe(name string, input []byte) bool {
	if !isProbeTool(name) || isLocalEditTool(name) {
		return false
	}
	if name == "Bash" && len(input) > 0 {
		var raw struct {
			Command string `json:"command"`
		}
		if json.Unmarshal(input, &raw) == nil && (isLocalReadOnlyBash(raw.Command) || isLocalWorkspaceWriteBash(raw.Command)) {
			return false
		}
	}
	return true
}

func isLocalWorkspaceWriteBashTool(name string, input []byte) bool {
	if name != "Bash" || len(input) == 0 {
		return false
	}
	var raw struct {
		Command string `json:"command"`
	}
	return json.Unmarshal(input, &raw) == nil && isLocalWorkspaceWriteBash(raw.Command)
}

var heredocSuffixRe = regexp.MustCompile(`<<-?\s*(?:'([A-Za-z_][A-Za-z0-9_]*)'|"([A-Za-z_][A-Za-z0-9_]*)"|([A-Za-z_][A-Za-z0-9_]*))\s*(?:2>/dev/null|2>&1)?\s*$`)

// isLocalWorkspaceWriteBash identifies pure local workspace file creation via
// heredoc (`[cd dir &&] [mkdir -p dir &&] cat > file <<'EOF' ... EOF` or `tee`),
// ensuring no network/execution command sits before or after the heredoc.
func isLocalWorkspaceWriteBash(command string) bool {
	s := strings.ReplaceAll(command, "\r\n", "\n")
	s = strings.TrimSpace(s)
	idx := strings.IndexByte(s, '\n')
	if idx <= 0 {
		return false
	}
	header := strings.TrimSpace(s[:idx])
	body := strings.TrimRight(s[idx+1:], " \t\n")
	if body == "" || header == "" {
		return false
	}
	if strings.ContainsAny(header, "|`") || strings.Contains(header, "$(") {
		return false
	}
	// Check heredoc delimiter at the end of header; also check forms like
	// `cat <<'EOF' > file.py` by stripping a trailing single output redirect first.
	headCheck := header
	if !heredocSuffixRe.MatchString(headCheck) {
		// Handle `cat <<'EOF' > file` (output redirect after heredoc opener).
		reRedirTail := regexp.MustCompile(`\s+>{1,2}\s*[^\s;&|]+\s*$`)
		headCheck = reRedirTail.ReplaceAllString(header, "")
	}
	m := heredocSuffixRe.FindStringSubmatch(headCheck)
	if m == nil {
		return false
	}
	delim := m[1]
	if delim == "" {
		delim = m[2]
	}
	if delim == "" {
		delim = m[3]
	}
	if delim == "" {
		return false
	}
	// Ensure delim closes strictly at the very end of body with no trailing commands.
	bodyLines := strings.Split(body, "\n")
	if len(bodyLines) == 0 || strings.TrimSpace(bodyLines[len(bodyLines)-1]) != delim {
		return false
	}
	for _, mid := range bodyLines[:len(bodyLines)-1] {
		if strings.TrimSpace(mid) == delim {
			return false
		}
	}

	segs, ok := splitSimpleHeaderSegments(header)
	if !ok || len(segs) == 0 {
		return false
	}
	for i, seg := range segs {
		fields := strings.Fields(seg)
		if len(fields) == 0 {
			return false
		}
		cmd := filepath.Base(fields[0])
		if i < len(segs)-1 {
			if cmd != "cd" && cmd != "mkdir" {
				return false
			}
			continue
		}
		switch cmd {
		case "cat":
			if !strings.Contains(seg, ">") {
				return false
			}
		case "tee":
		default:
			return false
		}
	}
	return true
}

func splitSimpleHeaderSegments(header string) ([]string, bool) {
	var segs []string
	var cur strings.Builder
	var quote byte
	escaped := false
	for i := 0; i < len(header); i++ {
		c := header[i]
		if escaped {
			cur.WriteByte(c)
			escaped = false
			continue
		}
		if quote == '\'' {
			if c == '\'' {
				quote = 0
			}
			cur.WriteByte(c)
			continue
		}
		if c == '\\' {
			cur.WriteByte(c)
			escaped = true
			continue
		}
		if quote == '"' {
			if c == '"' {
				quote = 0
			}
			cur.WriteByte(c)
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			cur.WriteByte(c)
			continue
		}
		if c == ';' || (c == '&' && i+1 < len(header) && header[i+1] == '&') {
			part := strings.TrimSpace(cur.String())
			if part == "" {
				return nil, false
			}
			segs = append(segs, part)
			cur.Reset()
			if c == '&' {
				i++
			}
			continue
		}
		if c == '&' || c == '|' || c == '<' && (i+1 >= len(header) || header[i+1] != '<') {
			// Single `<` input redirect or background `&` / pipe `|` rejected, EXCEPT `<<` heredoc.
			if c != '<' {
				return nil, false
			}
		}
		if c == '<' && i+1 < len(header) && header[i+1] == '<' {
			cur.WriteString("<<")
			i++
			continue
		}
		cur.WriteByte(c)
	}
	if quote != 0 || escaped {
		return nil, false
	}
	if part := strings.TrimSpace(cur.String()); part != "" {
		segs = append(segs, part)
	} else {
		return nil, false
	}
	return segs, true
}

var (
	obsUUIDRe = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	obsTSRe   = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?\b`)
	obsHexRe  = regexp.MustCompile(`(?i)\b(?:0x)?[0-9a-f]{8,}\b`)
	obsNumRe  = regexp.MustCompile(`\b\d{4,}\b`)
)

func observationSignature(result []byte, isErr bool) string {
	trimmed := strings.TrimSpace(string(result))
	if trimmed == "" {
		return ""
	}
	sample := trimmed
	if len(sample) > 4096 {
		sample = sample[:2048] + "\n...\n" + sample[len(sample)-2048:]
	}
	norm := obsUUIDRe.ReplaceAllString(sample, "<UUID>")
	norm = obsTSRe.ReplaceAllString(norm, "<TS>")
	norm = obsHexRe.ReplaceAllString(norm, "<HEX>")
	norm = obsNumRe.ReplaceAllString(norm, "<NUM>")
	norm = strings.Join(strings.Fields(norm), " ")
	bucket := bits.Len(uint(len(trimmed)))
	h := fnv.New64a()
	_, _ = h.Write([]byte(norm))
	return fmt.Sprintf("e=%t;b=%d;h=%016x", isErr, bucket, h.Sum64())
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
