package agent

import (
	"os"
	"strings"

	"github.com/Autumn-27/norma/harness"
)

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

func isWriteBackTool(name string) bool {
	switch name {
	case "record_fact", "insert_assets", "report_finding", "add_finding":
		return true
	default:
		return false
	}
}

// IntentStateAfterRun maps a finished worker run to an intent state.
// RunBudget exhaustion and max_turns/timeout yield the slot as exhausted
// (partial progress, never a target/goal failure, and never done).
func IntentStateAfterRun(reason harness.TerminalReason, runErr error) string {
	switch {
	case isRunBudgetError(runErr):
		return "exhausted"
	case IsCallTimeout(runErr):
		return "open" // 墙钟超时 ≠ 目标失败,也不标 blocked;用户取消不走这条
	case runErr != nil:
		return "blocked"
	case reason == harness.ReasonMaxTurns || reason == harness.ReasonTimeout:
		return "exhausted"
	default:
		return "done"
	}
}
