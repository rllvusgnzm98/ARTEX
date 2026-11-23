package agent

import (
	"context"
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
