package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

func tightPolicy() StopLossPolicy {
	return StopLossPolicy{
		SafetyCeiling:      DefaultSafetyCeiling,
		IdleProbeLimit:     2,
		RepeatCommandLimit: 2,
	}
}

func TestSafetyCeilingIsCapNotPrimaryStop(t *testing.T) {
	p := tightPolicy()
	// Progress continuing at 19 minutes: do not stop just because time passed.
	got := EvaluateStopLoss(p, ProgressSignals{
		FactsKnown: true, AssetsKnown: true, CommandsKnown: true,
		NewFacts: 1, NewAssets: 1, IdleProbes: 0, RepeatCount: 1,
		Elapsed: 19 * time.Minute,
	})
	if got.Fired() || got.Kind != StopLossNone {
		t.Fatalf("continuing progress before the cap must not stop: %+v", got)
	}

	// Same stall signals at 90s fire stop-loss without waiting for 20 minutes.
	early := EvaluateStopLoss(p, ProgressSignals{
		FactsKnown: true, AssetsKnown: true, CommandsKnown: true,
		NewFacts: 0, NewAssets: 0, IdleProbes: 2, RepeatCount: 1,
		Elapsed: 90 * time.Second,
	})
	if early.Kind != StopLossNoProgress || !early.Fired() {
		t.Fatalf("no-progress stop-loss must fire before the cap: %+v", early)
	}
	if early.TargetFailureWrites != 0 {
		t.Fatalf("stop-loss must not write target failure: %+v", early)
	}

	// No stall, but the cap has been reached: policy treats 20m as a ceiling.
	capHit := EvaluateStopLoss(p, ProgressSignals{
		FactsKnown: true, AssetsKnown: true, CommandsKnown: true,
		NewFacts: 2, NewAssets: 1, IdleProbes: 0, RepeatCount: 1,
		Elapsed: DefaultSafetyCeiling,
	})
	if capHit.Kind != StopLossSafetyCeiling || capHit.Fired() {
		t.Fatalf("20-minute value must be a cap, not an early stop-loss: %+v", capHit)
	}
	if capHit.TargetFailureWrites != 0 {
		t.Fatalf("ceiling must not write target failure: %+v", capHit)
	}

	// Stall wins over ceiling so the primary stop is stop-loss, not the clock.
	both := EvaluateStopLoss(p, ProgressSignals{
		FactsKnown: true, AssetsKnown: true, CommandsKnown: true,
		NewFacts: 0, NewAssets: 0, IdleProbes: 2,
		Elapsed: DefaultSafetyCeiling,
	})
	if both.Kind != StopLossNoProgress {
		t.Fatalf("when both could apply, stop-loss is the primary reason: %+v", both)
	}
}

func TestStopLossFiresOnNoNewFactsAssetsAndRepeatedCommands(t *testing.T) {
	p := tightPolicy()
	noProgress := EvaluateStopLoss(p, ProgressSignals{
		FactsKnown: true, AssetsKnown: true, CommandsKnown: true,
		NewFacts: 0, NewAssets: 0, NewFindings: 0, IdleProbes: 2,
		Elapsed: time.Minute,
	})
	if noProgress.Kind != StopLossNoProgress {
		t.Fatalf("expected no-progress stop, got %+v", noProgress)
	}

	// A finding is also marginal progress: do not stop only because facts/assets are 0.
	withFinding := EvaluateStopLoss(p, ProgressSignals{
		FactsKnown: true, AssetsKnown: true, CommandsKnown: true,
		NewFindings: 1, IdleProbes: 2, Elapsed: time.Minute,
	})
	if withFinding.Fired() {
		t.Fatalf("a new finding is progress, got %+v", withFinding)
	}

	repeat := EvaluateStopLoss(p, ProgressSignals{
		FactsKnown: true, AssetsKnown: true, CommandsKnown: true,
		NewFacts: 1, NewAssets: 1, RepeatCount: 2,
		Elapsed: time.Minute,
	})
	if repeat.Kind != StopLossRepeatedCommand {
		t.Fatalf("expected repeated-command stop, got %+v", repeat)
	}
	if !strings.Contains(repeat.Message(), StopLossMessagePrefix) {
		t.Fatalf("message should carry the stop-loss marker: %q", repeat.Message())
	}
}

func TestMissingSignalsFailSoft(t *testing.T) {
	p := tightPolicy()
	unknown := EvaluateStopLoss(p, ProgressSignals{
		FactsKnown: false, AssetsKnown: false, CommandsKnown: false,
		IdleProbes: 10, RepeatCount: 5, Elapsed: time.Minute,
	})
	if unknown.Fired() || unknown.Kind != StopLossNone {
		t.Fatalf("missing signals must fail-soft, got %+v", unknown)
	}
	if unknown.TargetFailureWrites != 0 {
		t.Fatalf("fail-soft must not write target/goal failure: %+v", unknown)
	}

	// Facts unknown: even with idle probes, do not hard-stop on no-progress.
	factsUnknown := EvaluateStopLoss(p, ProgressSignals{
		FactsKnown: false, AssetsKnown: true, CommandsKnown: true,
		IdleProbes: 10, RepeatCount: 1, Elapsed: time.Minute,
	})
	if factsUnknown.Fired() {
		t.Fatalf("unknown fact signal must not hard-stop: %+v", factsUnknown)
	}

	// Commands unknown: do not fire a repeat stop from an untrusted count.
	cmdsUnknown := EvaluateStopLoss(p, ProgressSignals{
		FactsKnown: true, AssetsKnown: true, CommandsKnown: false,
		NewFacts: 1, RepeatCount: 9, Elapsed: time.Minute,
	})
	if cmdsUnknown.Fired() {
		t.Fatalf("unknown command signal must not hard-stop: %+v", cmdsUnknown)
	}

	// The safety cap still applies when elapsed is known, even if other signals are missing.
	capWithGaps := EvaluateStopLoss(p, ProgressSignals{
		Elapsed: DefaultSafetyCeiling,
	})
	if capWithGaps.Kind != StopLossSafetyCeiling || capWithGaps.Fired() {
		t.Fatalf("missing signals must not disable the cap: %+v", capWithGaps)
	}
	if capWithGaps.TargetFailureWrites != 0 {
		t.Fatalf("cap on missing signals must not write target failure")
	}
}

func TestIntentStateAfterStopLossIsExhaustedNotFailure(t *testing.T) {
	loss := StopLossVerdict{Kind: StopLossNoProgress, Detail: "stalled"}
	if got := IntentStateAfterRun(harness.ReasonStopHookPrevented, nil, loss); got != "exhausted" {
		t.Fatalf("stop-loss should settle exhausted, got %s", got)
	}
	if got := IntentStateAfterRun(harness.ReasonCompleted, nil, loss); got != "exhausted" {
		t.Fatalf("fired stop-loss wins over completed, got %s", got)
	}
	if got := IntentStateAfterRun(harness.ReasonTimeout, nil, StopLossVerdict{}); got != "exhausted" {
		t.Fatalf("timeout cap should stay exhausted, got %s", got)
	}
	if got := IntentStateAfterRun(harness.ReasonCompleted, nil, StopLossVerdict{}); got != "done" {
		t.Fatalf("normal completion should stay done, got %s", got)
	}
	if got := IntentStateAfterRun(harness.ReasonCompleted, context.Canceled, loss); got != "blocked" {
		t.Fatalf("run error still maps to blocked, got %s", got)
	}
}

func TestStopLossHookEnforcedInCodeNotPrompt(t *testing.T) {
	mon := NewStopLossMonitor(tightPolicy())
	hooks := WrapStopLoss(nil, mon)
	cmd, _ := jsonCmd(`{"command":"curl https://edge.example.test/health"}`)

	// Two identical probes trip repeated-command stop-loss.
	hooks.PostToolUse(context.Background(), "Bash", cmd, []byte(`{"ok":true}`), false)
	if mon.Fired() {
		t.Fatal("first command is not a repeat")
	}
	hooks.PostToolUse(context.Background(), "Bash", cmd, []byte(`{"ok":true}`), false)
	if !mon.Fired() || mon.Verdict().Kind != StopLossRepeatedCommand {
		t.Fatalf("second identical command should stop-loss, got %+v", mon.Verdict())
	}
	if mon.Verdict().TargetFailureWrites != 0 {
		t.Fatal("hook must not write target failure")
	}

	// Further probes are blocked in PreToolUse — this is the hard guarantee.
	block, msg, _ := hooks.PreToolUse(context.Background(), "Bash", cmd)
	if !block || !strings.Contains(msg, StopLossMessagePrefix) {
		t.Fatalf("probe after stop-loss must be blocked by the hook, block=%v msg=%q", block, msg)
	}
	if block, _, _ := hooks.PreToolUse(context.Background(), "unrecognized_tool", nil); !block {
		t.Fatal("unrecognized tools must be blocked after stop-loss")
	}
	// Write-back remains allowed so already-identified facts can still be persisted.
	block, _, _ = hooks.PreToolUse(context.Background(), "record_fact", []byte(`{"summary":"x"}`))
	if block {
		t.Fatal("write-back tools must still be allowed after stop-loss")
	}

	prevent, _, stopMsg := hooks.Stop(context.Background(), nil)
	if !prevent || !strings.Contains(stopMsg, StopLossMessagePrefix) {
		t.Fatalf("Stop hook must prevent continuation, prevent=%v msg=%q", prevent, stopMsg)
	}

	// Decision does not depend on prompt text (dual insurance is the hook).
	promptOnly := EvaluateStopLoss(tightPolicy(), ProgressSignals{
		FactsKnown: true, AssetsKnown: true, CommandsKnown: true,
		NewFacts: 1, IdleProbes: 0, RepeatCount: 1, Elapsed: time.Minute,
	})
	if promptOnly.Fired() {
		t.Fatalf("policy must not fire from time alone or imagined prompt text: %+v", promptOnly)
	}
}

func TestStopLossLatchesFirstVerdictAndCounterSnapshot(t *testing.T) {
	policy := tightPolicy()
	policy.IdleProbeLimit = 1
	mon := NewStopLossMonitor(policy)
	hooks := WrapStopLoss(nil, mon)
	input, _ := jsonCmd(`{"command":"test"}`)
	hooks.PostToolUse(t.Context(), "Bash", input, nil, false)
	first := mon.Verdict()
	if first.Kind != StopLossNoProgress || first.Signals.IdleProbes != 1 || first.Signals.RepeatCount != 1 {
		t.Fatalf("first verdict = %+v", first)
	}
	hooks.PostToolUse(t.Context(), "Bash", input, nil, false)
	if later := mon.Verdict(); later != first {
		t.Fatalf("first verdict changed: first=%+v later=%+v", first, later)
	}
}

func TestStopLossHookNoProgressOnIdleProbes(t *testing.T) {
	mon := NewStopLossMonitor(tightPolicy())
	hooks := WrapStopLoss(nil, mon)
	a, _ := jsonCmd(`{"command":"probe edge.example.test:443"}`)
	b, _ := jsonCmd(`{"command":"probe app.example.test:443"}`)
	hooks.PostToolUse(context.Background(), "Bash", a, []byte("ok"), false)
	if mon.Fired() {
		t.Fatal("one distinct probe is still inside the idle window")
	}
	hooks.PostToolUse(context.Background(), "Bash", b, []byte("ok"), false)
	if !mon.Fired() || mon.Verdict().Kind != StopLossNoProgress {
		t.Fatalf("two idle probes with no writes should stop-loss, got %+v", mon.Verdict())
	}
}

func TestStopLossHookWriteResetsIdleWindow(t *testing.T) {
	mon := NewStopLossMonitor(tightPolicy())
	hooks := WrapStopLoss(nil, mon)
	a, _ := jsonCmd(`{"command":"probe edge.example.test:443"}`)
	hooks.PostToolUse(context.Background(), "Bash", a, []byte("ok"), false)
	hooks.PostToolUse(context.Background(), "record_fact", []byte(`{"summary":"edge reachable"}`), []byte(`{"id":1}`), false)
	b, _ := jsonCmd(`{"command":"probe app.example.test:443"}`)
	hooks.PostToolUse(context.Background(), "Bash", b, []byte("ok"), false)
	if mon.Fired() {
		t.Fatalf("a write should reset the idle window, got %+v", mon.Verdict())
	}
}

func TestStopLossHookFiresAfterWriteThenFullIdleWindow(t *testing.T) {
	// After one successful write, idling for a full window of distinct
	// probes must still fire no-progress. The write resets the window; it
	// does not permanently disable no-progress for the rest of the run.
	mon := NewStopLossMonitor(tightPolicy())
	hooks := WrapStopLoss(nil, mon)
	hooks.PostToolUse(context.Background(), "record_fact", []byte(`{"summary":"edge reachable"}`), []byte(`{"id":1}`), false)
	a, _ := jsonCmd(`{"command":"probe edge.example.test:443"}`)
	b, _ := jsonCmd(`{"command":"probe app.example.test:443"}`)
	hooks.PostToolUse(context.Background(), "Bash", a, []byte("ok"), false)
	if mon.Fired() {
		t.Fatalf("write + fewer than one idle window must not fire, got %+v", mon.Verdict())
	}
	hooks.PostToolUse(context.Background(), "Bash", b, []byte("ok"), false)
	v := mon.Verdict()
	if !mon.Fired() || v.Kind != StopLossNoProgress {
		t.Fatalf("idleLimit distinct probes after a write must fire no-progress, got %+v", v)
	}
	if v.TargetFailureWrites != 0 {
		t.Fatalf("stop-loss must not write target failure: %+v", v)
	}
}

func TestStopLossHookFiresAfterWriteThenFullIdleWindowWithCumulativeSnapshot(t *testing.T) {
	// Production AttachStopLossWrites overlays ToolSet.Writes(), which is a
	// whole-run total. After one fact write the snapshot stays at Facts=1
	// during later probes; no-progress must still fire on the idle window,
	// using a delta against the post-write baseline rather than the total.
	mon := NewStopLossMonitor(tightPolicy())
	writes := WriteCounts{}
	mon.SetWriteSnapshot(func() (WriteCounts, bool) { return writes, true })
	hooks := WrapStopLoss(nil, mon)

	writes.Facts = 1 // Writes() already includes this write when PostToolUse runs
	hooks.PostToolUse(context.Background(), "record_fact", []byte(`{"summary":"edge reachable"}`), []byte(`{"id":1}`), false)
	a, _ := jsonCmd(`{"command":"probe edge.example.test:443"}`)
	b, _ := jsonCmd(`{"command":"probe app.example.test:443"}`)
	hooks.PostToolUse(context.Background(), "Bash", a, []byte("ok"), false)
	if mon.Fired() {
		t.Fatalf("cumulative snapshot must not fire before a full idle window, got %+v", mon.Verdict())
	}
	hooks.PostToolUse(context.Background(), "Bash", b, []byte("ok"), false)
	v := mon.Verdict()
	if !mon.Fired() || v.Kind != StopLossNoProgress {
		t.Fatalf("cumulative Writes() snapshot must not block no-progress after a full idle window, got %+v", v)
	}
	if v.TargetFailureWrites != 0 {
		t.Fatalf("stop-loss must not write target failure: %+v", v)
	}
}

func TestStopLossHookMissingFingerprintFailSoft(t *testing.T) {
	mon := NewStopLossMonitor(tightPolicy())
	hooks := WrapStopLoss(nil, mon)
	// Empty / unparseable probe input cannot be compared; must not invent a repeat.
	hooks.PostToolUse(context.Background(), "Bash", nil, []byte("ok"), false)
	hooks.PostToolUse(context.Background(), "Bash", []byte("   "), []byte("ok"), false)
	if mon.Fired() {
		t.Fatalf("unfingerprintable commands must fail-soft, got %+v", mon.Verdict())
	}
	block, _, _ := hooks.PreToolUse(context.Background(), "Bash", []byte(`{"command":"x"}`))
	if block {
		t.Fatal("fail-soft must not hard-block probes")
	}
	prevent, _, _ := hooks.Stop(context.Background(), []llm.Message{})
	if prevent {
		t.Fatal("fail-soft must not prevent continuation")
	}
}

func TestStopLossHookUnknownWriteSnapshotFailSoft(t *testing.T) {
	mon := NewStopLossMonitor(tightPolicy())
	mon.SetWriteSnapshot(func() (WriteCounts, bool) { return WriteCounts{}, false })
	hooks := WrapStopLoss(nil, mon)
	a, _ := jsonCmd(`{"command":"probe-one"}`)
	b, _ := jsonCmd(`{"command":"probe-two"}`)
	hooks.PostToolUse(context.Background(), "Bash", a, []byte("ok"), false)
	hooks.PostToolUse(context.Background(), "Bash", b, []byte("ok"), false)
	if mon.Fired() {
		t.Fatalf("unknown write snapshot must not fire no-progress stop, got %+v", mon.Verdict())
	}
}

func TestDefaultPolicyTreatsTwentyMinutesAsCeiling(t *testing.T) {
	p := DefaultStopLossPolicy()
	if p.SafetyCeiling != DefaultSafetyCeiling || DefaultSafetyCeiling != 20*time.Minute {
		t.Fatalf("default cap must be 20 minutes, got %v", p.SafetyCeiling)
	}
	if p.SafetyCeiling != 1200*time.Second {
		t.Fatalf("cap must match run_seconds=1200, got %v", p.SafetyCeiling)
	}
}

func jsonCmd(s string) ([]byte, []byte) {
	return []byte(s), []byte(s)
}

func TestStopLossRemindsBeforeLatch(t *testing.T) {
	// A write-back reminder appears one probe before the no_progress latch when
	// explicitly enabled in policy, blocking that probe and handing a message to the
	// model — without altering idle counter or firing stop-loss.
	p := tightPolicy()
	p.WriteBackReminder = true
	mon := NewStopLossMonitor(p) // idle limit 2 → remind at 1
	hooks := WrapStopLoss(nil, mon)
	a, _ := jsonCmd(`{"command":"probe edge.example.test:443"}`)
	hooks.PostToolUse(context.Background(), "Bash", a, []byte("ok"), false)
	if mon.Fired() {
		t.Fatal("one idle probe must not latch yet")
	}
	block, msg, _ := hooks.PreToolUse(context.Background(), "Bash", []byte(`{"command":"probe app.example.test:443"}`))
	if !block || !strings.Contains(msg, StopLossWriteBackReminderPrefix) {
		t.Fatalf("expected a write-back reminder before the latch, got block=%v msg=%q", block, msg)
	}
	if mon.Fired() {
		t.Fatalf("the reminder must not be a stop-loss, got %+v", mon.Verdict())
	}
	// One-shot: the same idle window does not remind again.
	block2, _, _ := hooks.PreToolUse(context.Background(), "Bash", []byte(`{"command":"probe other.example.test:443"}`))
	if block2 {
		t.Fatal("reminder must fire at most once per idle window")
	}
}

func TestStopLossReminderDoesNotFireOnFreshWindow(t *testing.T) {
	// With no idle probes yet, a probe must run untouched (no reminder).
	mon := NewStopLossMonitor(DefaultStopLossPolicy())
	hooks := WrapStopLoss(nil, mon)
	block, _, _ := hooks.PreToolUse(context.Background(), "Bash", []byte(`{"command":"probe edge.example.test:443"}`))
	if block {
		t.Fatal("a fresh idle window must not trigger a write-back reminder")
	}
}

func TestStopLossReminderResetsAfterWriteBack(t *testing.T) {
	// A real write-back resets the idle window, so the reminder can fire again
	// in the next window — and a worker that keeps writing never latches.
	p := tightPolicy()
	p.WriteBackReminder = true
	mon := NewStopLossMonitor(p)
	hooks := WrapStopLoss(nil, mon)
	a, _ := jsonCmd(`{"command":"probe edge.example.test:443"}`)
	hooks.PostToolUse(context.Background(), "Bash", a, []byte("ok"), false)
	block, _, _ := hooks.PreToolUse(context.Background(), "Bash", []byte(`{"command":"probe app.example.test:443"}`))
	if !block {
		t.Fatal("expected first-window reminder")
	}
	// Worker heeds it and writes a fact: window resets, nudge flag clears.
	hooks.PostToolUse(context.Background(), "record_fact", []byte(`{"summary":"edge reachable"}`), []byte(`{"id":1}`), false)
	if mon.Fired() {
		t.Fatalf("a write-back must not latch, got %+v", mon.Verdict())
	}
	b, _ := jsonCmd(`{"command":"probe app.example.test:443"}`)
	hooks.PostToolUse(context.Background(), "Bash", b, []byte("ok"), false)
	block2, msg2, _ := hooks.PreToolUse(context.Background(), "Bash", []byte(`{"command":"probe deep.example.test:443"}`))
	if !block2 || !strings.Contains(msg2, StopLossWriteBackReminderPrefix) {
		t.Fatalf("reminder must fire again in a fresh idle window, got block=%v", block2)
	}
}

func TestStopLossReminderDoesNotAlterLatch(t *testing.T) {
	// If the worker ignores the reminder and keeps probing with nothing new,
	// no_progress still fires at exactly the idle limit — the reminder only
	// inserted one blocked round, it did not move the threshold.
	p := tightPolicy()
	p.WriteBackReminder = true
	mon := NewStopLossMonitor(p) // limit 2
	hooks := WrapStopLoss(nil, mon)
	a, _ := jsonCmd(`{"command":"probe edge.example.test:443"}`)
	hooks.PostToolUse(context.Background(), "Bash", a, []byte("ok"), false) // idle 1
	block, _, _ := hooks.PreToolUse(context.Background(), "Bash", []byte(`{"command":"probe app.example.test:443"}`))
	if !block {
		t.Fatal("expected reminder at idle limit-1")
	}
	// Blocked call did not execute, so idle is still 1 and nothing latched.
	if mon.Fired() {
		t.Fatalf("blocked reminder must not latch, got %+v", mon.Verdict())
	}
	b, _ := jsonCmd(`{"command":"probe app.example.test:443"}`)
	hooks.PostToolUse(context.Background(), "Bash", b, []byte("ok"), false) // idle 2 → latch
	if !mon.Fired() || mon.Verdict().Kind != StopLossNoProgress {
		t.Fatalf("no_progress must still fire at the idle limit, got %+v", mon.Verdict())
	}
	// Once latched, the reminder path yields to the stop-loss block.
	_, msg, _ := hooks.PreToolUse(context.Background(), "Bash", []byte(`{"command":"probe x"}`))
	if !strings.Contains(msg, StopLossMessagePrefix) {
		t.Fatalf("after latch, a probe must get the stop-loss message, got %q", msg)
	}
}

type pendingSteerHooks struct{ pending bool }

func (h pendingSteerHooks) PreToolUse(context.Context, string, []byte) (bool, string, []byte) {
	if h.pending {
		return true, "steer", nil
	}
	return false, "", nil
}
func (pendingSteerHooks) PostToolUse(context.Context, string, []byte, []byte, bool) {}
func (pendingSteerHooks) Stop(context.Context, []llm.Message) (bool, []string, string) {
	return false, nil, ""
}
func (h pendingSteerHooks) SteerPending() bool { return h.pending }

func TestStopLossReminderYieldsToPendingSteer(t *testing.T) {
	// A queued operator correction wins over the write-back reminder, and the
	// reminder stays available for the next call in the same window.
	p := tightPolicy()
	p.WriteBackReminder = true
	mon := NewStopLossMonitor(p)
	a, _ := jsonCmd(`{"command":"probe edge.example.test:443"}`)
	steered := WrapStopLoss(pendingSteerHooks{pending: true}, mon)
	steered.PostToolUse(context.Background(), "Bash", a, []byte("ok"), false)
	block, msg, _ := steered.PreToolUse(context.Background(), "Bash", []byte(`{"command":"probe app.example.test:443"}`))
	if !block || msg != "steer" {
		t.Fatalf("expected the pending steer to be delivered, got block=%v msg=%q", block, msg)
	}
	plain := WrapStopLoss(pendingSteerHooks{}, mon)
	block, msg, _ = plain.PreToolUse(context.Background(), "Bash", []byte(`{"command":"probe app.example.test:443"}`))
	if !block || !strings.Contains(msg, StopLossWriteBackReminderPrefix) {
		t.Fatalf("reminder must still fire after the steer is gone, got block=%v msg=%q", block, msg)
	}
}

func TestStopLossDefaultPolicyAndEnvOverrides(t *testing.T) {
	t.Setenv("ARTEX_STOPLOSS_IDLE_PROBES", "")
	t.Setenv("ARTEX_STOPLOSS_REPEAT_LIMIT", "")
	t.Setenv("ARTEX_STOPLOSS_NOVEL_RELIEF", "")
	t.Setenv("ARTEX_STOPLOSS_WRITE_REMINDER", "")
	def := DefaultStopLossPolicy()
	if def.IdleProbeLimit != 24 || def.RepeatCommandLimit != 3 || def.MaxNovelRelief != 16 || def.WriteBackReminder {
		t.Fatalf("default policy = %+v, want 24/3/16/WriteBackReminder=false", def)
	}
	t.Setenv("ARTEX_STOPLOSS_IDLE_PROBES", "18")
	t.Setenv("ARTEX_STOPLOSS_REPEAT_LIMIT", "5")
	t.Setenv("ARTEX_STOPLOSS_NOVEL_RELIEF", "24")
	t.Setenv("ARTEX_STOPLOSS_WRITE_REMINDER", "1")
	over := DefaultStopLossPolicy()
	if over.IdleProbeLimit != 18 || over.RepeatCommandLimit != 5 || over.MaxNovelRelief != 24 || !over.WriteBackReminder {
		t.Fatalf("env override policy = %+v, want 18/5/24/true", over)
	}
}

func TestStopLossMultiToolTurnReminderHoldsAllSiblings(t *testing.T) {
	// Norma executes all tool calls in a single assistant turn before returning
	// tool results to the model. Once the reminder triggers on the first probe
	// of a turn, sibling probes in the SAME turn must also be held so they
	// cannot slip through and latch no_progress before the model sees the nudge.
	p := tightPolicy()
	p.IdleProbeLimit = 3
	p.WriteBackReminder = true
	mon := NewStopLossMonitor(p)
	hooks := WrapStopLoss(nil, mon)

	mon.BeginModelTurn()
	a, _ := jsonCmd(`{"command":"curl https://a.example.test/1"}`)
	hooks.PostToolUse(context.Background(), "Bash", a, []byte("ok"), false)
	mon.BeginModelTurn()
	b, _ := jsonCmd(`{"command":"curl https://a.example.test/2"}`)
	hooks.PostToolUse(context.Background(), "Bash", b, []byte("ok"), false)

	// Next turn emits TWO probes in parallel (idle == limit-1 == 2):
	mon.BeginModelTurn()
	c, _ := jsonCmd(`{"command":"curl https://a.example.test/3"}`)
	d, _ := jsonCmd(`{"command":"curl https://a.example.test/4"}`)
	block1, msg1, _ := hooks.PreToolUse(context.Background(), "Bash", c)
	block2, msg2, _ := hooks.PreToolUse(context.Background(), "Bash", d)
	if !block1 || !strings.Contains(msg1, StopLossWriteBackReminderPrefix) {
		t.Fatalf("first probe should be held with reminder, got block=%v msg=%q", block1, msg1)
	}
	if !block2 || !strings.Contains(msg2, StopLossWriteBackReminderPrefix) {
		t.Fatalf("same-turn sibling probe must also be held with reminder, got block=%v msg=%q", block2, msg2)
	}
	if mon.Fired() {
		t.Fatalf("reminder-held sibling turn must not latch stop-loss, verdict=%+v", mon.Verdict())
	}

	// On the NEXT model turn, if the model still ignores the reminder and probes,
	// it is allowed through so PostToolUse can latch no_progress cleanly.
	mon.BeginModelTurn()
	if block3, msg3, _ := hooks.PreToolUse(context.Background(), "Bash", c); block3 {
		t.Fatalf("next-turn probe after reminder should proceed to latch, got block=%v msg=%q", block3, msg3)
	}
}

func TestStopLossLocalEditsAndLocalReadOnlyBashExemptFromIdle(t *testing.T) {
	p := tightPolicy()
	p.IdleProbeLimit = 2
	p.RepeatCommandLimit = 5
	mon := NewStopLossMonitor(p)

	// Local file authoring and local read-only shell commands must not burn idle budget.
	mon.ObserveTool("Write", []byte(`{"file_path":"/tmp/exp.py","content":"v1"}`), false)
	mon.ObserveTool("Edit", []byte(`{"file_path":"/tmp/exp.py","old_string":"v1","new_string":"v2"}`), false)
	mon.ObserveTool("MultiEdit", []byte(`{"file_path":"/tmp/exp.py","edits":[]}`), false)
	mon.ObserveTool("Bash", []byte(`{"command":"ls -la /tmp && cat /tmp/exp.py | head -n 5"}`), false)
	mon.ObserveTool("Bash", []byte(`{"command":"grep -n foo /tmp/exp.py"}`), false)
	if v := mon.Recompute(); v.Fired() || v.Signals.IdleProbes != 0 {
		t.Fatalf("local edits/reads should not increment IdleProbes, got verdict=%+v", v)
	}

	// Network-facing recon command (dig) and active probe (curl) DO count.
	mon.ObserveTool("Bash", []byte(`{"command":"dig target.example.test"}`), false)
	mon.ObserveTool("Bash", []byte(`{"command":"curl https://target.example.test/"}`), false)
	if v := mon.Recompute(); !v.Fired() || v.Kind != StopLossNoProgress || v.Signals.IdleProbes != 2 {
		t.Fatalf("network probes must trip no_progress at limit=2, got %+v", v)
	}
}

func TestStopLossEditClearsBashRepeatsAndWriteBackClearsAllRepeats(t *testing.T) {
	p := tightPolicy()
	p.IdleProbeLimit = 20
	p.RepeatCommandLimit = 3
	mon := NewStopLossMonitor(p)

	runExp, _ := jsonCmd(`{"command":"python3 exploit.py"}`)
	mon.ObserveTool("Bash", runExp, false)
	mon.ObserveTool("Bash", runExp, false) // count=2 (<3)
	// Editing the script should reset Bash repeat counts so re-running is not a false loop.
	mon.ObserveTool("Edit", []byte(`{"file_path":"exploit.py","old_string":"a","new_string":"b"}`), false)
	mon.ObserveTool("Bash", runExp, false) // count=1 after reset
	mon.ObserveTool("Bash", runExp, false) // count=2
	if v := mon.Recompute(); v.Fired() {
		t.Fatalf("re-running edited script must not trigger repeated_command: %+v", v)
	}

	// Write-back (record_fact) also resets repeats for the new window.
	mon.ObserveTool("record_fact", []byte(`{"summary":"progress"}`), false)
	mon.ObserveTool("Bash", runExp, false) // count=1
	mon.ObserveTool("Bash", runExp, false) // count=2
	if v := mon.Recompute(); v.Fired() {
		t.Fatalf("write-back must reset repeat window: %+v", v)
	}

	// Repeating identical Write 3 times without progress STILL trips repeated_command.
	sameWrite := []byte(`{"file_path":"exploit.py","content":"unchanged"}`)
	mon.ObserveTool("Write", sameWrite, false)
	mon.ObserveTool("Write", sameWrite, false)
	mon.ObserveTool("Write", sameWrite, false)
	if v := mon.Recompute(); !v.Fired() || v.Kind != StopLossRepeatedCommand {
		t.Fatalf("identical Write loop must still trip repeated_command, got %+v", v)
	}
}

func TestStopLossPostLatchAllowsAllWriteBackTools(t *testing.T) {
	p := tightPolicy()
	p.IdleProbeLimit = 1
	mon := NewStopLossMonitor(p)
	hooks := WrapStopLoss(nil, mon)

	mon.ObserveTool("Bash", []byte(`{"command":"curl https://t.example.test/"}`), false)
	if !mon.Recompute().Fired() {
		t.Fatal("expected stop-loss to latch")
	}

	// All 4 write-back tools must remain allowed after stop-loss latches.
	for _, tool := range []string{"record_fact", "insert_assets", "report_finding", "add_finding"} {
		block, msg, _ := hooks.PreToolUse(context.Background(), tool, []byte(`{}`))
		if block {
			t.Fatalf("post-stop-loss %s must be allowed, got blocked: %q", tool, msg)
		}
	}
	// Non-write-back execution tools remain blocked.
	for _, tool := range []string{"Bash", "Write", "Edit"} {
		block, msg, _ := hooks.PreToolUse(context.Background(), tool, []byte(`{}`))
		if !block || !strings.Contains(msg, "record_fact") || !strings.Contains(msg, "report_finding") {
			t.Fatalf("post-stop-loss %s must be blocked with write-back guidance, block=%v msg=%q", tool, block, msg)
		}
	}
}

func bashJSON(cmd string) []byte {
	b, _ := json.Marshal(map[string]string{"command": cmd})
	return b
}

func TestStopLossLocalMultilineAndReversingBashExempt(t *testing.T) {
	p := tightPolicy()
	p.IdleProbeLimit = 2
	p.RepeatCommandLimit = 3
	mon := NewStopLossMonitor(p)

	exempt := []string{
		"cd /tmp/work\ngrep -ohE 'api' *.js 2>/dev/null",
		"cd /tmp/work && ls -la; cat out.txt | head -n 20",
		"objdump -d validator | head -n 30",
		"readelf -s validator 2>&1",
		"sed -n 80,216p jdwp.py",
		"cd /tmp/work && python3 - <<'EOF'\nimport re\nprint(re.findall(r'a', 'aba'))\nEOF",
	}
	for _, cmd := range exempt {
		mon.ObserveTool("Bash", bashJSON(cmd), false)
	}
	if v := mon.Recompute(); v.Fired() || mon.Signals().IdleProbes != 0 {
		t.Fatalf("local multiline/reversing/offline-python commands must not consume IdleProbes, got %+v sig=%+v", v, mon.Signals())
	}

	// Network-enabled python3 or active curl MUST still consume IdleProbes.
	mon.ObserveTool("Bash", bashJSON(`python3 -c "import requests; print(requests.get('http://10.0.0.1'))"`), false)
	mon.ObserveTool("Bash", bashJSON(`curl -s http://10.0.0.1/`), false)
	if v := mon.Recompute(); !v.Fired() || v.Kind != StopLossNoProgress || v.Signals.IdleProbes != 2 {
		t.Fatalf("network python/curl must trip no_progress at limit=2, got %+v", v)
	}

	// Repeating the identical local command 3 times still triggers repeated_command.
	mon2 := NewStopLossMonitor(StopLossPolicy{IdleProbeLimit: 20, RepeatCommandLimit: 3})
	sameLocal := bashJSON("objdump -d validator")
	mon2.ObserveTool("Bash", sameLocal, false)
	mon2.ObserveTool("Bash", sameLocal, false)
	mon2.ObserveTool("Bash", sameLocal, false)
	if v := mon2.Recompute(); !v.Fired() || v.Kind != StopLossRepeatedCommand {
		t.Fatalf("repeating identical local command 3 times must still trip repeated_command, got %+v", v)
	}
}

func TestStopLossPostLatchAllowsSingleCleanupClose(t *testing.T) {
	p := tightPolicy()
	p.IdleProbeLimit = 1
	mon := NewStopLossMonitor(p)
	hooks := WrapStopLoss(nil, mon)

	mon.ObserveTool("Bash", []byte(`{"command":"curl https://t.example.test/"}`), false)
	if !mon.Recompute().Fired() {
		t.Fatal("expected stop-loss to latch")
	}

	closeCmd := bashJSON(`curl -s -X POST -H "BENCHMARK_TOKEN: abc" -A "$ARTEX_UA" "https://bench.example.test/openapi/v1/challenges/close?unique_code=c-03"`)
	if block, msg, _ := hooks.PreToolUse(context.Background(), "Bash", closeCmd); block {
		t.Fatalf("first post-latch /close call must be allowed, got blocked: %q", msg)
	}
	// A second cleanup call is blocked (one-shot only).
	if block, _, _ := hooks.PreToolUse(context.Background(), "Bash", closeCmd); !block {
		t.Fatal("second post-latch /close call must be blocked")
	}
	// Non-cleanup Bash commands remain blocked even before cleanup is used.
	mon2 := NewStopLossMonitor(p)
	hooks2 := WrapStopLoss(nil, mon2)
	mon2.ObserveTool("Bash", []byte(`{"command":"curl https://t.example.test/"}`), false)
	mon2.Recompute()
	for _, bad := range []string{
		`curl https://bench.example.test/login`,
		`curl -X POST https://bench.example.test/login`,
		`rm -rf /tmp/x`,
		`curl -X POST https://bench.example.test/close && id`,
	} {
		if block, _, _ := hooks2.PreToolUse(context.Background(), "Bash", bashJSON(bad)); !block {
			t.Fatalf("non-cleanup post-latch Bash %q must be blocked", bad)
		}
	}
}

func TestStopLossDefaultWriteReminderDisabled(t *testing.T) {
	t.Setenv("ARTEX_STOPLOSS_WRITE_REMINDER", "")
	p := tightPolicy()
	mon := NewStopLossMonitor(p)
	hooks := WrapStopLoss(nil, mon)
	a, _ := jsonCmd(`{"command":"curl https://a.example.test/"}`)
	hooks.PostToolUse(context.Background(), "Bash", a, []byte("ok"), false)
	block, msg, _ := hooks.PreToolUse(context.Background(), "Bash", []byte(`{"command":"curl https://b.example.test/"}`))
	if block || strings.Contains(msg, StopLossWriteBackReminderPrefix) {
		t.Fatalf("default policy must not block with pre-latch write-back reminder, got block=%v msg=%q", block, msg)
	}
}

func TestStopLossNoveltyReliefAndNoiseNormalization(t *testing.T) {
	p := StopLossPolicy{IdleProbeLimit: 2, RepeatCommandLimit: 5, MaxNovelRelief: 4}
	mon := NewStopLossMonitor(p)
	hooks := WrapStopLoss(nil, mon)

	// 1st probe sets baseline (idle=1), followed by 3 genuinely distinct outputs (status/stack changes):
	// idle must stay at 1 because novel outputs consume novelty relief rather than idle budget.
	hooks.PostToolUse(context.Background(), "Bash", bashJSON("curl http://10.0.0.1/1"), []byte("HTTP/1.1 200 OK login form"), false)
	hooks.PostToolUse(context.Background(), "Bash", bashJSON("curl http://10.0.0.1/2"), []byte("HTTP/1.1 500 Internal Server Error sqlite syntax"), false)
	hooks.PostToolUse(context.Background(), "Bash", bashJSON("curl http://10.0.0.1/3"), []byte("HTTP/1.1 302 Found Location: /admin"), false)
	hooks.PostToolUse(context.Background(), "Bash", bashJSON("curl http://10.0.0.1/4"), []byte("root:x:0:0:root:/root:/bin/bash"), false)
	if mon.Fired() || mon.Signals().IdleProbes != 1 {
		t.Fatalf("distinct outputs must stay unlatched with idle=1, got verdict=%+v sig=%+v", mon.Verdict(), mon.Signals())
	}

	// Homogeneous 404 responses differing only in UUID/timestamp/nonce must normalize to the same
	// signature, advance idle on repetition, and latch no_progress cleanly.
	hooks.PostToolUse(context.Background(), "Bash", bashJSON("curl http://10.0.0.1/a"), []byte("HTTP/1.1 404 Not Found req=123e4567-e89b-12d3-a456-426614174000 ts=2026-11-24T12:00:01Z"), false)
	if mon.Fired() {
		t.Fatalf("first 404 response is a novel class and should not latch yet, got %+v", mon.Verdict())
	}
	hooks.PostToolUse(context.Background(), "Bash", bashJSON("curl http://10.0.0.1/b"), []byte("HTTP/1.1 404 Not Found req=987e6543-e89b-12d3-a456-426614179999 ts=2026-11-24T12:00:05Z"), false)
	if !mon.Fired() || mon.Verdict().Kind != StopLossNoProgress {
		t.Fatalf("normalized homogeneous 404 probes must fire no_progress, got %+v", mon.Verdict())
	}
}

func TestStopLossLocalHeredocWriteBashExemptAndClearsRepeats(t *testing.T) {
	p := StopLossPolicy{IdleProbeLimit: 4, RepeatCommandLimit: 3, MaxNovelRelief: 0}
	mon := NewStopLossMonitor(p)
	hooks := WrapStopLoss(nil, mon)

	// Two repeated runs of python3 exp.py...
	runExp := bashJSON("cd /tmp/w && python3 exp.py")
	hooks.PostToolUse(context.Background(), "Bash", runExp, []byte("try1"), false)
	hooks.PostToolUse(context.Background(), "Bash", runExp, []byte("try1"), false)

	// Writing a modified script via local heredoc cat does NOT count toward IdleProbes
	// and resets prior Bash repeats.
	writeScript := bashJSON("cd /tmp/w && cat > spray.php <<'EOF'\n<?php system($_GET['c']); curl_init(); ?>\nEOF")
	hooks.PostToolUse(context.Background(), "Bash", writeScript, []byte(""), false)
	if sig := mon.Signals(); sig.IdleProbes != 2 || sig.RepeatCount != 1 {
		t.Fatalf("heredoc write must exempt idle and clear prior bash repeats, got %+v", sig)
	}

	// Appending an external command after closing delimiter MUST NOT be treated as pure local write.
	unsafeHeredoc := "cat > spray.php <<'EOF'\nhello\nEOF\ncurl http://10.0.0.1/"
	if isLocalWorkspaceWriteBash(unsafeHeredoc) {
		t.Fatal("heredoc with trailing command must not be exempted")
	}
}

func TestStopLossReportFindingGrantsMilestoneBonus(t *testing.T) {
	p := StopLossPolicy{IdleProbeLimit: 2, RepeatCommandLimit: 10, MaxNovelRelief: -1}
	mon := NewStopLossMonitor(p)
	hooks := WrapStopLoss(nil, mon)

	// report_finding grants +6 idle bonus (effective limit becomes 2+6=8).
	hooks.PostToolUse(context.Background(), "report_finding", []byte(`{"name":"SQLi","summary":"found"}`), []byte(`{"finding_id":1}`), false)
	for i := 0; i < 6; i++ {
		hooks.PostToolUse(context.Background(), "Bash", bashJSON("curl http://10.0.0.1/p"), []byte("same"), false)
		if mon.Fired() {
			t.Fatalf("milestone bonus should keep run alive at probe %d, verdict=%+v", i+1, mon.Verdict())
		}
	}
}

