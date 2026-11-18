package agent

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/Autumn-27/artex/llmpool"
	"github.com/Autumn-27/norma/harness"
)

func TestClassifySupplyFailureSignals(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err    error
		signal string
	}{
		{errors.New("provider: status 403: forbidden"), SupplyHTTP403},
		{errors.New("HTTP 403 Forbidden"), SupplyHTTP403},
		{errors.New("HTTP status 403: billing_hard_limit_reached"), SupplyHTTP403},
		{errors.New("openai: status 402: payment required"), SupplyHTTP402},
		{errors.New("HTTP status 402 Payment Required"), SupplyHTTP402},
		{errors.New("provider: status 401: invalid api key"), SupplyHTTP401},
		{errors.New("You exceeded your current quota, please check your plan and billing details."), SupplyQuotaExhausted},
		{errors.New("billing_hard_limit_reached"), SupplyQuotaExhausted},
		{errors.New("账户余额不足，请充值"), SupplyQuotaExhausted},
		{llmpool.ErrExhausted, SupplyChainExhausted},
		{fmt.Errorf("%w：%v", llmpool.ErrExhausted, errors.New("status 402: no credit")), SupplyChainExhausted},
		{fmt.Errorf("wrap: %w", ErrProviderChainExhausted), SupplyChainExhausted},
	}
	for _, tc := range cases {
		got, ok := ClassifySupplyFailure(tc.err)
		if !ok || got.Signal != tc.signal {
			t.Errorf("err=%v: got %+v ok=%v, want signal %s", tc.err, got, ok, tc.signal)
		}
	}
}

func TestClassifySupplyFailureRejectsNonSupply(t *testing.T) {
	t.Parallel()
	negatives := []error{
		nil,
		errors.New("HTTP status 429: rate limit exceeded"),
		errors.New("RESOURCE_EXHAUSTED: TPM quota exceeded"),
		errors.New("HTTP status 429: quota exceeded for quota metric GenerateRequestsPerMinute"),
		errors.New("HTTP status 500: internal server error"),
		errors.New("HTTP status 503: quota_exceeded"),
		errors.New("status 400: invalid request parameter"),
		errors.New("dial tcp: connection reset by peer"),
		errors.New("context length exceeded"),
		context.Canceled,
		context.DeadlineExceeded,
		fmt.Errorf("canceled: %w", context.Canceled),
	}
	for _, err := range negatives {
		if class, ok := ClassifySupplyFailure(err); ok {
			t.Errorf("misclassified as supply failure: err=%v class=%+v", err, class)
		}
	}
}

func TestSupplySettlementDoesNotMarkBlockedOrDone(t *testing.T) {
	t.Parallel()
	errs := []error{
		errors.New("status 403: forbidden"),
		errors.New("status 402: payment required"),
		errors.New("insufficient_quota"),
		fmt.Errorf("%w: %v", ErrProviderChainExhausted, errors.New("status 402")),
	}
	for _, err := range errs {
		s := SettleWorkerRun(harness.ReasonModelError, err)
		if !s.SupplyFailure || s.TerminalKind != TerminalSupplyInterrupt {
			t.Fatalf("settle=%+v, want supply interrupt", s)
		}
		if s.IntentState == "blocked" || s.IntentState == "done" {
			t.Fatalf("intent state %q must not be blocked or done", s.IntentState)
		}
		if s.IntentState != SupplyIntentParkState {
			t.Fatalf("intent state=%q, want park %q", s.IntentState, SupplyIntentParkState)
		}
		if s.TaskStatus == "done" || s.TaskStatus == "failed" || s.TaskStatus == "blocked" {
			t.Fatalf("task status %q must stay unset (running scene)", s.TaskStatus)
		}
		if !s.FreezeScene {
			t.Fatal("fallback/provider exhaustion must freeze the scene")
		}
		if s.AllowRedispatch {
			t.Fatal("must not allow empty re-dispatch while supply-failed")
		}
		wrote := 0
		s = s.ApplyTargetFailure(func() { wrote++ })
		if s.TargetFailureWrites != 0 || wrote != 0 {
			t.Fatalf("TargetFailureWrites=%d wrote=%d, want 0", s.TargetFailureWrites, wrote)
		}
	}
}

func TestFallbackExhaustedFreezesAndPreservesScene(t *testing.T) {
	t.Parallel()
	type scene struct {
		Session, Graph, Progress bool
		IntentState, TaskStatus  string
	}
	sc := scene{Session: true, Graph: true, Progress: true, IntentState: "running", TaskStatus: "running"}
	s := SettleWorkerRun(harness.ReasonModelError, fmt.Errorf("%w：%v", llmpool.ErrExhausted, errors.New("status 402")))
	if !s.FreezeScene || s.TerminalKind != TerminalSupplyInterrupt {
		t.Fatalf("expected freeze + supply interrupt, got %+v", s)
	}
	// Applying the settlement parks the intent and leaves the rest of the scene.
	sc.IntentState = s.IntentState
	if s.TaskStatus != "" {
		sc.TaskStatus = s.TaskStatus
	}
	if !sc.Session || !sc.Graph || !sc.Progress {
		t.Fatal("freeze must keep session, graph, and progress")
	}
	if sc.IntentState != "open" {
		t.Fatalf("intent=%q, want parked open", sc.IntentState)
	}
	if sc.TaskStatus != "running" {
		t.Fatalf("task status=%q, want running (not success/done)", sc.TaskStatus)
	}
}

func TestNoIdleRedispatchWhileSupplyFailed(t *testing.T) {
	t.Parallel()
	claims := 0
	for i := 0; i < 8; i++ {
		if ShouldDispatch(true) {
			claims++
		}
	}
	if claims != 0 {
		t.Fatalf("idle re-dispatch claims=%d, want 0 while frozen", claims)
	}
	if !ShouldDispatch(false) {
		t.Fatal("unfrozen workers must still be allowed to claim")
	}
}

func TestEmptyCompletionIsDistinctFromSupplyInterrupt(t *testing.T) {
	t.Parallel()
	empty := SettleWorkerRun(harness.ReasonCompleted, nil)
	if empty.TerminalKind != TerminalCompleted || empty.IntentState != "done" || empty.SupplyFailure {
		t.Fatalf("empty run should complete successfully, got %+v", empty)
	}
	if empty.FreezeScene || !empty.AllowRedispatch {
		t.Fatalf("empty completion must not freeze the scene: %+v", empty)
	}
	supply := SettleWorkerRun(harness.ReasonModelError, errors.New("status 402: payment required"))
	if !DistinctTerminals(empty.TerminalKind, supply.TerminalKind) {
		t.Fatalf("empty completion %q must be distinct from supply interrupt %q", empty.TerminalKind, supply.TerminalKind)
	}
	abandoned := SettleWorkerRun(harness.ReasonCompleted, nil)
	if abandoned.TerminalKind == TerminalSupplyInterrupt {
		t.Fatal("abandoned/empty completion must not reuse the supply-interrupt terminal")
	}
}

func TestNonSupplyErrorsStillSettleAsBlocked(t *testing.T) {
	t.Parallel()
	s := SettleWorkerRun(harness.ReasonModelError, errors.New("dial tcp: connection reset by peer"))
	if s.SupplyFailure || s.FreezeScene || s.IntentState != "blocked" || s.TerminalKind != TerminalTargetBlocked {
		t.Fatalf("transport error misclassified: %+v", s)
	}
	if !s.AllowRedispatch {
		t.Fatal("non-supply errors must not freeze the whole dispatcher")
	}

	budget := SettleWorkerRun(harness.ReasonMaxTurns, nil)
	if budget.SupplyFailure || budget.IntentState != "exhausted" || budget.TerminalKind != TerminalBudgetExhausted {
		t.Fatalf("max turns misclassified: %+v", budget)
	}
	timeout := SettleWorkerRun(harness.ReasonTimeout, nil)
	if timeout.SupplyFailure || timeout.IntentState != "exhausted" {
		t.Fatalf("timeout misclassified: %+v", timeout)
	}
}

func TestSingleProviderChainDoesNotRequireSecondModel(t *testing.T) {
	t.Parallel()
	// A one-member chain that surfaces 402 is enough to freeze. No second
	// profile is required, matching the existing optional llmpool failover.
	s := SettleWorkerRun(harness.ReasonModelError, errors.New("status 402: payment required"))
	if !s.SupplyFailure || !s.FreezeScene {
		t.Fatalf("single-provider 402 should freeze without a mandatory fallback, got %+v", s)
	}
}
