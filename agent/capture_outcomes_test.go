package agent

import (
	"reflect"
	"testing"

	"github.com/Autumn-27/artex/db"
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
