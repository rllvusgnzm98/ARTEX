package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

// SettlementTransientError wraps a run-budget or call-timeout error whose
// recovery settlement phase failed due to a transient LLM outage/stream error
// after retries inside the reserve window. server/engine.go uses
// IsSettlementTransientError to distinguish this from a normal ReasonTimeout
// exhaustion without changing Worker.Execute's signature.
type SettlementTransientError struct {
	BudgetErr   error
	RecoveryErr error
}

func (e *SettlementTransientError) Error() string {
	if e == nil {
		return ""
	}
	if e.BudgetErr != nil && e.RecoveryErr != nil {
		return fmt.Sprintf("%v (settlement transient error: %v)", e.BudgetErr, e.RecoveryErr)
	}
	if e.RecoveryErr != nil {
		return fmt.Sprintf("settlement transient error: %v", e.RecoveryErr)
	}
	if e.BudgetErr != nil {
		return e.BudgetErr.Error()
	}
	return "settlement transient error"
}

func (e *SettlementTransientError) Unwrap() error {
	if e == nil {
		return nil
	}
	if e.BudgetErr != nil {
		return e.BudgetErr
	}
	return e.RecoveryErr
}

// IsSettlementTransientError reports whether err is (or wraps) a
// *SettlementTransientError.
func IsSettlementTransientError(err error) bool {
	var ste *SettlementTransientError
	return errors.As(err, &ste)
}

var (
	// settlementRetryBackoffs defines exponential retry delays inside the 120s
	// reserve window when settlement fails with a transient stream/network error.
	// Package-level vars allow deterministic fast unit tests.
	settlementRetryBackoffs  = []time.Duration{3 * time.Second, 6 * time.Second, 12 * time.Second}
	settlementMinRetryRemain = 10 * time.Second
)

// isTransientSettlementError identifies transient transport, stream, or upstream
// 5xx/429 outages during settlement that warrant retrying inside the reserve window.
// Explicit cancellations, run-budget expiry, supply/auth failures, and WAF 403
// blocks return false.
func isTransientSettlementError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || isRunBudgetError(err) {
		return false
	}
	if IsSupplyFailure(err) || IsGatewayWAFBlock(err) {
		return false
	}
	if IsCallTimeout(err) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	switch HTTPStatusOf(err) {
	case 429, 500, 502, 503, 504, 520, 522, 524:
		return true
	}
	s := strings.ToLower(err.Error())
	for _, tok := range []string{
		"connection refused",
		"connection reset",
		"broken pipe",
		"unexpected eof",
		"eof",
		"stream",
		"timed out",
		"i/o timeout",
		"timeout",
		"tls handshake",
		"dial tcp",
		"no such host",
		"temporarily unavailable",
		"bad gateway",
		"service unavailable",
		"gateway timeout",
		"overloaded",
		"rate limit",
		"empty response",
		"no choices",
	} {
		if strings.Contains(s, tok) {
			return true
		}
	}
	return false
}

func (w *Worker) recoverSettlement(ctx context.Context, previous *agentcore.Session, opts agentcore.Options, settle *harness.Settlement, runErr error, tsx *ToolSet, emit func(db.Activity)) error {
	b, ok := ctx.Value(runBudgetKey{}).(runBudget)
	if !ok || b.reserve <= 0 || ctx.Err() != nil || (!isRunBudgetError(runErr) && !IsCallTimeout(runErr)) {
		return nil
	}
	why := "run_budget"
	hard := b.hardDeadline()
	if IsCallTimeout(runErr) {
		why = "call_timeout"
		hard = minTime(hard, time.Now().Add(b.reserve))
	}
	if time.Until(hard) < 5*time.Second {
		return nil
	}
	b.hard = hard
	freezeRunBudgetExtension(ctx)
	b.ext = nil
	start, before := time.Now(), tsx.Writes()
	var calls atomic.Int64
	var recoveryErr error
	var snapshotMsgs []llm.Message
	if previous != nil {
		snapshotMsgs = previous.Messages()
	}
	defer func() {
		after := tsx.Writes()
		writes := WriteCounts{Facts: after.Facts - before.Facts, Assets: after.Assets - before.Assets, Findings: after.Findings - before.Findings}
		log.Printf("[worker settlement] reason=%s duration=%s turns=%d writes=%s error=%v", why, time.Since(start), calls.Load(), writes, recoveryErr)
	}()

	opts.SessionID = previous.SessionID()
	if opts.Transcript == nil {
		dir, err := os.MkdirTemp(w.workDir, ".settlement-")
		if err != nil {
			recoveryErr = err
			return recoveryErr
		}
		defer os.RemoveAll(dir)
		opts.Transcript = transcript.NewStore(dir)
		messages := snapshotMsgs
		records := make([]transcript.Record, len(messages))
		for i := range messages {
			records[i] = transcript.Record{UUID: transcript.NewSessionID(), SessionID: opts.SessionID, Type: "message", Message: &messages[i]}
		}
		if err := opts.Transcript.Append(opts.Transcript.MainPath(opts.SessionID), records...); err != nil {
			recoveryErr = err
			return recoveryErr
		}
	}
	_ = previous.Close()
	tools := make([]actool.CoreTool, 0, len(opts.Tools))
	for _, tool := range opts.Tools {
		disabled := false
		for _, name := range settle.DisabledTools {
			disabled = disabled || tool.Name() == name
		}
		if !disabled {
			tools = append(tools, tool)
		}
	}
	opts.Tools, opts.Settlement = tools, nil
	opts.MaxTurns, opts.MaxDuration = settle.MaxTurns, time.Until(hard)
	opts.Provider = &runBudgetProvider{inner: opts.Provider, calls: &calls}
	b.recovery = true
	ctx = context.WithValue(ctx, runBudgetKey{}, b)
	s := agentcore.NewSession(opts)
	defer s.Close()
	if recoveryErr = s.Resume(opts.SessionID); recoveryErr != nil {
		return recoveryErr
	}
	if len(s.Messages()) == 0 {
		recoveryErr = errors.New("settlement transcript is empty")
		return recoveryErr
	}
	if len(snapshotMsgs) == 0 {
		snapshotMsgs = s.Messages()
	}
	prompt := settle.Prompt
	if isRunBudgetError(runErr) {
		if p := settle.PromptByReason[harness.ReasonTimeout]; p != "" {
			prompt = p
		}
	}

	// Attempt settlement with bounded exponential backoff inside the reserve
	// window on transient stream/network errors (3s -> 6s -> 12s while >10s remain).
	for attempt := 0; ; attempt++ {
		_, _, recoveryErr = captureRunSession(ctx, s, prompt, emit)
		if recoveryErr == nil {
			return nil
		}
		if ctx.Err() != nil || !isTransientSettlementError(recoveryErr) {
			break
		}
		if attempt >= len(settlementRetryBackoffs) {
			break
		}
		remain := time.Until(hard)
		if remain <= settlementMinRetryRemain {
			break
		}
		wait := settlementRetryBackoffs[attempt]
		if maxWait := remain - settlementMinRetryRemain; wait > maxWait {
			wait = maxWait
		}
		if wait > 0 {
			log.Printf("[worker settlement] transient error (attempt=%d/%d, retry_in=%s, remain=%s): %v",
				attempt+1, len(settlementRetryBackoffs)+1, wait.Round(time.Millisecond), remain.Round(time.Millisecond), recoveryErr)
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return recoveryErr
			case <-timer.C:
			}
		}
		if time.Until(hard) <= settlementMinRetryRemain {
			break
		}
	}

	// All settlement LLM attempts failed. If nothing was written back during
	// settlement, persist a deterministic partial_progress fact summarizing the
	// last observed tool calls/outputs so work is never silently lost.
	after := tsx.Writes()
	wroteDuringSettlement := (after.Facts-before.Facts)+(after.Assets-before.Assets)+(after.Findings-before.Findings) > 0
	if !wroteDuringSettlement && tsx != nil && tsx.ts != nil && ctx.Err() == nil {
		msgs := s.Messages()
		if len(msgs) == 0 {
			msgs = snapshotMsgs
		}
		w.recordDeterministicPartialProgress(ctx, tsx, msgs, why, recoveryErr)
	}
	return recoveryErr
}

type observedToolStep struct {
	name   string
	input  string
	output string
	isErr  bool
	done   bool
}

func extractObservedToolSteps(messages []llm.Message, maxSteps int) []observedToolStep {
	if maxSteps <= 0 {
		maxSteps = 6
	}
	var steps []observedToolStep
	idxByID := map[string]int{}
	for _, msg := range messages {
		for _, blk := range msg.Content {
			switch blk.Type {
			case llm.BlockToolUse:
				name := strings.TrimSpace(blk.Name)
				if name == "" {
					continue
				}
				in := db.RedactCredentialPayload(name, strings.TrimSpace(string(blk.Input)))
				idxByID[blk.ID] = len(steps)
				steps = append(steps, observedToolStep{
					name:  name,
					input: clipPlainRunes(strings.Join(strings.Fields(in), " "), 120),
				})
			case llm.BlockToolResult:
				text := strings.TrimSpace(blocksText(blk.Content))
				if idx, ok := idxByID[blk.ToolUseID]; ok {
					out := db.RedactCredentialPayload(steps[idx].name, text)
					steps[idx].output = clipPlainRunes(strings.Join(strings.Fields(out), " "), 220)
					steps[idx].isErr = blk.IsError
					steps[idx].done = true
				} else if text != "" {
					out := db.RedactCredentialPayload("", text)
					steps = append(steps, observedToolStep{
						name:   "tool",
						output: clipPlainRunes(strings.Join(strings.Fields(out), " "), 220),
						isErr:  blk.IsError,
						done:   true,
					})
				}
			}
		}
	}
	if len(steps) > maxSteps {
		steps = steps[len(steps)-maxSteps:]
	}
	return steps
}

func (w *Worker) recordDeterministicPartialProgress(ctx context.Context, tsx *ToolSet, messages []llm.Message, reason string, recoveryErr error) {
	steps := extractObservedToolSteps(messages, 6)
	if len(steps) == 0 {
		return
	}
	var detail strings.Builder
	fmt.Fprintf(&detail, "partial_progress（结算原因=%s，结算 LLM 错误=%s）；自动保存最近 %d 步已观察工具调用与输出：\n",
		reason, clipPlainRunes(recoveryErr.Error(), 160), len(steps))
	var lastEvidence string
	for i, st := range steps {
		status := "ok"
		if !st.done {
			status = "pending"
		} else if st.isErr {
			status = "error"
		}
		fmt.Fprintf(&detail, "%d. %s [%s] input=%s", i+1, st.name, status, st.input)
		if st.output != "" {
			fmt.Fprintf(&detail, " => %s", st.output)
			lastEvidence = fmt.Sprintf("%s: %s", st.name, clipPlainRunes(st.output, 140))
		} else if lastEvidence == "" {
			lastEvidence = fmt.Sprintf("%s(%s)", st.name, clipPlainRunes(st.input, 120))
		}
		detail.WriteByte('\n')
	}
	summary := fmt.Sprintf("[partial_progress] 结算阶段遭遇模型故障，已自动保存最近 %d 步工具观察进展", len(steps))
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if _, err := tsx.recordOneFactCtx(writeCtx, factItem{
		Summary:    summary,
		Detail:     strings.TrimSpace(detail.String()),
		Evidence:   lastEvidence,
		Confidence: "observed",
	}, tsx.ownerNode); err != nil {
		log.Printf("[worker settlement] deterministic partial_progress fallback write failed: %v", err)
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
