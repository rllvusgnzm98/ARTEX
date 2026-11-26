package agent

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/harness"
)

func TestToolActivityOutcomes(t *testing.T) {
	activities := []db.Activity{{Kind: "tool_result", IsError: true}, {Kind: "tool_use"}}
	for _, tc := range []struct {
		result, want string
		isError      bool
	}{
		{"Blocked by hook: 【止损】", "policy_blocked", true},
		{"Tool call was not permitted: denied", "policy_blocked", true},
		{"Error: failed to run", "tool_error", true},
		{"Blocked by hook: text in a successful result", "executed", false},
		{"Error: unknown tool \"missing\"", "unknown", true},
	} {
		got := toolActivityOutcome(tc.result, tc.isError)
		if got != tc.want {
			t.Errorf("toolActivityOutcome(%q, %t) = %q, want %q", tc.result, tc.isError, got, tc.want)
		}
		activities = append(activities, db.Activity{Kind: "tool_result", IsError: tc.isError, Metadata: outcomeMetadata(got)})
	}
	want := map[string]int{"executed": 1, "tool_error": 1, "policy_blocked": 2, "unknown": 2}
	if got := db.SummarizeToolActivityOutcomes(activities); !reflect.DeepEqual(got, want) {
		t.Fatalf("summary = %v, want %v", got, want)
	}
}

func TestTerminalTextRunBudgetAndCallTimeoutNotMisclassifiedAsModelError(t *testing.T) {
	tr := &runTrace{startedAt: time.Now().Add(-100 * time.Millisecond)}
	for i := range 54 {
		id := string(rune('a' + (i % 26)))
		tr.start(id, "Bash", `{}`)
		tr.done(id)
	}

	budgetTerm := &harness.Terminal{
		Reason: harness.ReasonModelError,
		Turns:  12,
		Err:    &RunBudgetError{Deadline: time.Now()},
	}
	norm, isErr := normalizeTerminalForActivity(budgetTerm)
	if norm.Reason != harness.ReasonTimeout || isErr {
		t.Fatalf("normalizeTerminalForActivity(RunBudgetError) = (%q, %v), want (%q, false)", norm.Reason, isErr, harness.ReasonTimeout)
	}
	sum, detail := terminalText(context.Background(), budgetTerm, tr)
	if !strings.Contains(sum, "timeout") || !strings.Contains(sum, "54 次工具调用") {
		t.Fatalf("runBudget terminal summary missing timeout or tool call count: %q", sum)
	}
	if strings.Contains(sum, "model_error") || strings.Contains(detail, "model_error") || strings.Contains(detail, "基本没真正探成") {
		t.Fatalf("runBudget misclassified as model_error:\nsum=%s\ndetail=%s", sum, detail)
	}

	idleErr := &StreamIdleTimeoutError{Idle: time.Minute}
	idleTerm := &harness.Terminal{
		Reason: harness.ReasonModelError,
		Turns:  5,
		Err:    idleErr,
	}
	sum2, detail2 := terminalText(context.Background(), idleTerm, tr)
	if !strings.Contains(sum2, "call_timeout") || !strings.Contains(detail2, "call_timeout") {
		t.Fatalf("call_timeout not surfaced:\nsum=%s\ndetail=%s", sum2, detail2)
	}
	if strings.Contains(detail2, "基本没真正探成") {
		t.Fatalf("call_timeout wrongly says 0-probe failure:\n%s", detail2)
	}
}
