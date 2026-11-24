package agent

import (
	"context"
	"errors"
	"log"
	"os"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/harness"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

func (w *Worker) recoverSettlement(ctx context.Context, previous *agentcore.Session, opts agentcore.Options, settle *harness.Settlement, runErr error, tsx *ToolSet, emit func(db.Activity)) {
	b, ok := ctx.Value(runBudgetKey{}).(runBudget)
	if !ok || b.reserve <= 0 || ctx.Err() != nil || (!isRunBudgetError(runErr) && !IsCallTimeout(runErr)) {
		return
	}
	why := "run_budget"
	hard := b.hardDeadline()
	if IsCallTimeout(runErr) {
		why = "call_timeout"
		hard = minTime(hard, time.Now().Add(b.reserve))
	}
	if time.Until(hard) < 5*time.Second {
		return
	}
	b.hard = hard
	b.ext = nil
	start, before := time.Now(), tsx.Writes()
	var calls atomic.Int64
	var recoveryErr error
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
			return
		}
		defer os.RemoveAll(dir)
		opts.Transcript = transcript.NewStore(dir)
		messages := previous.Messages()
		records := make([]transcript.Record, len(messages))
		for i := range messages {
			records[i] = transcript.Record{UUID: transcript.NewSessionID(), SessionID: opts.SessionID, Type: "message", Message: &messages[i]}
		}
		if err := opts.Transcript.Append(opts.Transcript.MainPath(opts.SessionID), records...); err != nil {
			recoveryErr = err
			return
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
		return
	}
	if len(s.Messages()) == 0 {
		recoveryErr = errors.New("settlement transcript is empty")
		return
	}
	prompt := settle.Prompt
	if isRunBudgetError(runErr) {
		if p := settle.PromptByReason[harness.ReasonTimeout]; p != "" {
			prompt = p
		}
	}
	_, _, recoveryErr = captureRunSession(ctx, s, prompt, emit)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
