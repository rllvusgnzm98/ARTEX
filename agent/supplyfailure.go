package agent

import (
	"context"
	"errors"
	"regexp"
	"strconv"

	"github.com/Autumn-27/artex/llmpool"
	"github.com/Autumn-27/norma/harness"
)

// ErrProviderChainExhausted is the sentinel for "every configured provider
// (or the only provider) failed with a supply error". Callers wrap or
// errors.Is-match this; the existing llmpool.ErrExhausted also counts.
var ErrProviderChainExhausted = errors.New("LLM provider chain exhausted")

// Terminal kinds for one worker run. "Empty run finished" success must not
// share a terminal with a supply interrupt.
const (
	TerminalCompleted       = "completed"
	TerminalSupplyInterrupt = "supply_interrupt"
	TerminalTargetBlocked   = "target_blocked"
	TerminalBudgetExhausted = "budget_exhausted"
	TerminalLLMTransient    = "llm_transient" // 单次 LLM 墙钟超时:可重试,≠ 目标失败,≠ 供应冻结
)

// Supply signals that can be reported without treating the run as a target failure.
const (
	SupplyHTTP401        = "http_401"
	SupplyHTTP402        = "http_402"
	SupplyHTTP403        = "http_403"
	SupplyQuotaExhausted = "quota_exhausted"
	SupplyChainExhausted = "chain_exhausted"
)

// SupplyIntentParkState is the recoverable intent state used on a supply
// interrupt. It is deliberately not "blocked" and not "done": the scene
// (session, graph, already-written progress) stays, and the intent can be
// reclaimed after recovery or a human unfreeze.
const SupplyIntentParkState = "open"

// httpStatusRe pulls an HTTP status out of provider error text. The SDK has
// no typed status error; messages look like "status 402: ..." or "HTTP 403".
var httpStatusRe = regexp.MustCompile(`(?i)(?:status(?:\s+code)?|http(?:\s+status)?)\s*[=:]?\s*(\d{3})\b`)

// HTTPStatusOf returns the HTTP status carried by err, or 0 if there isn't one.
func HTTPStatusOf(err error) int {
	if err == nil {
		return 0
	}
	m := httpStatusRe.FindStringSubmatch(err.Error())
	if m == nil {
		return 0
	}
	code, _ := strconv.Atoi(m[1])
	return code
}

// IsSupplyFailure reports whether err is a provider/billing/auth exhaustion
// (402, 403, 401, explicit quota, or an exhausted failover chain). Transient
// rate limits, 5xx, network faults, and cancelled contexts are not supply
// failures — those keep the existing model-error / blocked path.
func IsSupplyFailure(err error) bool {
	_, ok := ClassifySupplyFailure(err)
	return ok
}

// SupplyClass is a classified supply-failure signal.
type SupplyClass struct {
	Signal string
}

// ClassifySupplyFailure identifies a supply failure. ok is false for nil,
// cancellations, and non-supply errors (429, 5xx, transport, 400, etc.).
func ClassifySupplyFailure(err error) (SupplyClass, bool) {
	if err == nil {
		return SupplyClass{}, false
	}
	if isContextError(err) {
		return SupplyClass{}, false
	}
	if errors.Is(err, ErrProviderChainExhausted) || errors.Is(err, llmpool.ErrExhausted) {
		return SupplyClass{Signal: SupplyChainExhausted}, true
	}
	switch code := HTTPStatusOf(err); code {
	case 401:
		return SupplyClass{Signal: SupplyHTTP401}, true
	case 402:
		return SupplyClass{Signal: SupplyHTTP402}, true
	case 403:
		return SupplyClass{Signal: SupplyHTTP403}, true
	}
	if IsQuotaExhaustedMessage(err.Error()) {
		return SupplyClass{Signal: SupplyQuotaExhausted}, true
	}
	return SupplyClass{}, false
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// RunSettlement is the durable outcome of one worker run. The engine applies
// it; tests assert the invariants without going through the loop.
type RunSettlement struct {
	IntentState         string
	TerminalKind        string
	Signal              string
	SupplyFailure       bool
	FreezeScene         bool
	AllowRedispatch     bool
	TargetFailureWrites int
	TaskStatus          string // empty = leave the task running; never "done"/"failed" on supply
}

// SettleWorkerRun maps a harness terminal + error onto intent/task outcomes.
// A supply interrupt never settles as blocked, done, or a target failure, and
// it never shares TerminalKind with an empty successful completion.
func SettleWorkerRun(reason harness.TerminalReason, err error) RunSettlement {
	if class, ok := ClassifySupplyFailure(err); ok {
		return RunSettlement{
			IntentState:         SupplyIntentParkState,
			TerminalKind:        TerminalSupplyInterrupt,
			Signal:              class.Signal,
			SupplyFailure:       true,
			FreezeScene:         true,
			AllowRedispatch:     false,
			TargetFailureWrites: 0,
			TaskStatus:          "",
		}
	}
	if IsCallTimeout(err) {
		// 墙钟超时可走 llmpool 转移;转移耗尽后仍不是目标失败,也不可标供应 blocked。
		// 意图回场为 open,现场不冻结,允许后续再派发。
		return RunSettlement{
			IntentState:         "open",
			TerminalKind:        TerminalLLMTransient,
			Signal:              "call_timeout",
			AllowRedispatch:     true,
			TargetFailureWrites: 0,
			TaskStatus:          "",
		}
	}
	if err != nil {
		return RunSettlement{
			IntentState:         "blocked",
			TerminalKind:        TerminalTargetBlocked,
			AllowRedispatch:     true,
			TargetFailureWrites: 0, // non-supply transport faults are not target failures either
		}
	}
	switch reason {
	case harness.ReasonMaxTurns, harness.ReasonTimeout:
		return RunSettlement{
			IntentState:     "exhausted",
			TerminalKind:    TerminalBudgetExhausted,
			AllowRedispatch: true,
		}
	default:
		return RunSettlement{
			IntentState:     "done",
			TerminalKind:    TerminalCompleted,
			AllowRedispatch: true,
		}
	}
}

// ShouldDispatch reports whether a worker may claim or start a new intent.
// During a supply freeze this is false: no idle re-assign, no empty spin.
func ShouldDispatch(frozen bool) bool {
	return !frozen
}

// ApplyTargetFailure records a target/goal failure write if and only if the
// settlement allows it. Supply interrupts always leave TargetFailureWrites at 0.
func (s RunSettlement) ApplyTargetFailure(write func()) RunSettlement {
	if s.SupplyFailure || s.TerminalKind == TerminalSupplyInterrupt || s.TerminalKind == TerminalLLMTransient {
		return s
	}
	if write != nil {
		write()
	}
	s.TargetFailureWrites++
	return s
}

// DistinctFrom reports whether two terminal kinds are different names.
func DistinctTerminals(a, b string) bool {
	return a != "" && b != "" && a != b
}

// SupplyFreezeSummary is the operator-facing one-line reason for a freeze.
func SupplyFreezeSummary() string {
	return "供应故障，现场已冻结，等待恢复或人工（不是目标失败，也不是任务完成）"
}
