package agent

import (
	"context"
	"strings"
	"testing"
)

func plannerProbeHooksFor(facts func() (int, bool)) (*plannerProbeState, interface {
	PreToolUse(context.Context, string, []byte) (bool, string, []byte)
}) {
	st := &plannerProbeState{}
	return st, WrapPlannerProbe(nil, st, PlannerProbeLimit, facts).(interface {
		PreToolUse(context.Context, string, []byte) (bool, string, []byte)
	})
}

func noFacts() (int, bool) { return 0, true }

// Boundary 1: once workers have produced facts, the planner may not probe at all.
func TestPlannerProbeBlockedOnceWorkerFactsExist(t *testing.T) {
	_, hooks := plannerProbeHooksFor(func() (int, bool) { return 4, true })

	for _, tool := range []string{"Bash", "WebFetch"} {
		block, msg, _ := hooks.PreToolUse(context.Background(), tool, []byte(`{"command":"curl https://t.example.test/"}`))
		if !block || !strings.Contains(msg, PlannerProbeMessagePrefix) {
			t.Fatalf("%s must be blocked once worker facts exist, block=%v msg=%q", tool, block, msg)
		}
		if !strings.Contains(msg, "add_intent") {
			t.Fatalf("block message should redirect to add_intent, got %q", msg)
		}
	}
}

// The origin fact alone is not a worker fact, so the opening allowance survives it.
// (CountWorkerFacts excludes state='origin'; here that means a 0 count still probes.)
func TestPlannerProbeAllowedAtOpening(t *testing.T) {
	_, hooks := plannerProbeHooksFor(noFacts)
	block, msg, _ := hooks.PreToolUse(context.Background(), "Bash", []byte(`{"command":"curl https://t.example.test/"}`))
	if block {
		t.Fatalf("opening probe with no worker facts must be allowed, msg=%q", msg)
	}
}

// Boundary 2: the opening allowance is finite.
func TestPlannerProbeCappedAtLimit(t *testing.T) {
	_, hooks := plannerProbeHooksFor(noFacts)
	cmd := []byte(`{"command":"curl https://t.example.test/"}`)

	for i := 0; i < PlannerProbeLimit; i++ {
		if block, msg, _ := hooks.PreToolUse(context.Background(), "Bash", cmd); block {
			t.Fatalf("probe %d/%d must be allowed, msg=%q", i+1, PlannerProbeLimit, msg)
		}
	}
	block, msg, _ := hooks.PreToolUse(context.Background(), "Bash", cmd)
	if !block || !strings.Contains(msg, PlannerProbeMessagePrefix) {
		t.Fatalf("probe past the cap must be blocked, block=%v msg=%q", block, msg)
	}
}

// The cap is per task, not per planning round: a fresh Plan() session reuses the
// same state, so the allowance cannot reset on every wake-up.
func TestPlannerProbeCapPersistsAcrossRounds(t *testing.T) {
	st := &plannerProbeState{}
	cmd := []byte(`{"command":"curl https://t.example.test/"}`)

	// Each round builds a new hook runner over the same per-task state.
	for i := 0; i < PlannerProbeLimit; i++ {
		round := WrapPlannerProbe(nil, st, PlannerProbeLimit, noFacts)
		if block, _, _ := round.PreToolUse(context.Background(), "Bash", cmd); block {
			t.Fatalf("probe %d must be allowed", i+1)
		}
	}
	later := WrapPlannerProbe(nil, st, PlannerProbeLimit, noFacts)
	if block, _, _ := later.PreToolUse(context.Background(), "Bash", cmd); !block {
		t.Fatal("a later planning round must not get a fresh probe allowance")
	}
}

// Planning, graph reads and intent generation are never touched by the boundary.
func TestPlannerProbeLeavesPlanningToolsAlone(t *testing.T) {
	_, hooks := plannerProbeHooksFor(func() (int, bool) { return 99, true })

	for _, tool := range []string{"add_intent", "graph_overview", "node_detail", "list_facts", "prove_goal", "Read", "LS", "Grep", "Glob", "TodoWrite"} {
		if block, msg, _ := hooks.PreToolUse(context.Background(), tool, nil); block {
			t.Fatalf("%s is a planning tool and must stay available, msg=%q", tool, msg)
		}
	}
}

// An unavailable fact count fails soft on boundary 1 — it must not be read as an
// empty graph — while the opening cap still bounds probing.
func TestPlannerProbeFactLookupFailsSoft(t *testing.T) {
	_, hooks := plannerProbeHooksFor(func() (int, bool) { return 0, false })
	cmd := []byte(`{"command":"curl https://t.example.test/"}`)

	for i := 0; i < PlannerProbeLimit; i++ {
		if block, msg, _ := hooks.PreToolUse(context.Background(), "Bash", cmd); block {
			t.Fatalf("fact lookup failure must fail soft on probe %d, msg=%q", i+1, msg)
		}
	}
	if block, _, _ := hooks.PreToolUse(context.Background(), "Bash", cmd); !block {
		t.Fatal("the probe cap must still apply when the fact count is unavailable")
	}
}

// A nil state or non-positive limit must not install a blocking wrapper.
func TestWrapPlannerProbeNoOp(t *testing.T) {
	if h := WrapPlannerProbe(nil, nil, PlannerProbeLimit, noFacts); h != nil {
		t.Fatal("nil state must be a no-op wrapper")
	}
	if h := WrapPlannerProbe(nil, &plannerProbeState{}, 0, noFacts); h != nil {
		t.Fatal("non-positive limit must be a no-op wrapper")
	}
}
