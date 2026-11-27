package agent

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

// The planner is the intent generator, not an executor. Its prompt grants one
// narrow exception — at the very opening, when the graph has no worker fact yet
// and the situation alone can't make the first intent concrete, it may run a
// couple of read-only probes (1–2 curls) purely to phrase a sharper intent — and
// then states three hard boundaries on it:
//
//  1. once the graph holds any worker-produced fact, probing is forbidden;
//  2. even at the opening, at most PlannerProbeLimit probes;
//  3. anything decidable from existing facts needs no probe at all.
//
// Those boundaries used to live only in the prompt, while the planner was handed
// the full default tool set (Bash included) plus WebFetch and no stop-loss
// monitor — so a planner that ignored them could probe without limit, outside the
// per-intent budget the worker's stop-loss enforces. plannerProbeHooks enforces
// boundaries 1 and 2 in the harness, the same way stopLossHooks enforces
// stop-loss in code rather than trusting the prompt.
const PlannerProbeLimit = 3

// PlannerProbeMessagePrefix marks a block as the planner probe boundary, so the
// model (and tests) can tell it apart from a stop-loss or permission refusal.
const PlannerProbeMessagePrefix = "【规划者探测边界】"

// plannerProbeTools are the planner's target-facing execution tools (shell,
// HTTP fetch, and external MCP tools). Local read-only inspection
// (Read/LS/Glob/Grep) and artifact writing are untouched: the boundaries are
// about probing the target, not about touching files.
func isPlannerProbeTool(name string) bool {
	switch name {
	case "Bash", "WebFetch":
		return true
	}
	return strings.HasPrefix(name, "mcp__")
}

// plannerProbeState is one task's opening-probe allowance. Each Plan() is a fresh
// session but the planner is woken repeatedly, so the count is kept per
// exploration on the Planner (like the todo scratchpad) — otherwise "at most 3 at
// the opening" would reset to 3 on every wake-up and bound nothing.
type plannerProbeState struct {
	mu   sync.Mutex
	used int
}

// take consumes one probe, reporting whether it was still within the cap.
func (s *plannerProbeState) take(limit int) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used >= limit {
		return s.used, false
	}
	s.used++
	return s.used, true
}

// plannerProbeHooks wraps an inner HookRunner and enforces the planner's probe
// boundaries in PreToolUse.
type plannerProbeHooks struct {
	inner harness.HookRunner
	state *plannerProbeState
	limit int
	// facts reports this task's worker-produced fact count. ok=false means the
	// count is unavailable (DB error); that signal then fails soft — boundary 1
	// is skipped rather than guessed, while the probe cap still applies.
	facts func() (int, bool)
}

// WrapPlannerProbe composes planner probe enforcement with an existing hook
// runner. A nil state or non-positive limit is a no-op wrapper.
func WrapPlannerProbe(inner harness.HookRunner, state *plannerProbeState, limit int, facts func() (int, bool)) harness.HookRunner {
	if state == nil || limit <= 0 {
		return inner
	}
	return plannerProbeHooks{inner: inner, state: state, limit: limit, facts: facts}
}

func (h plannerProbeHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	if isPlannerProbeTool(name) {
		// Boundary 1: workers have already produced facts — plan from the graph.
		if h.facts != nil {
			if n, ok := h.facts(); ok && n > 0 {
				return true, fmt.Sprintf("%s图中已有 worker 产出的 %d 条事实，规划者不得再自行探测：一切判断基于已有事实（需要细节用 node_detail/list_facts 回查），想深挖某条线索请用 add_intent 派给 worker，别自己 curl。（查看任务目录或 shared/ 本地文件请直接用 Read / LS / Glob / Grep，切勿用 Bash）", PlannerProbeMessagePrefix, n), nil
			}
		}
		// Boundary 2: the opening allowance is finite.
		if used, ok := h.state.take(h.limit); !ok {
			return true, fmt.Sprintf("%s开局探测额度已用满（%d/%d 次，跨本任务所有规划轮共享）。探测的唯一合法产物是一句更精准的意图描述——现在就把已看到的写成 add_intent 派给 worker，枚举/验证/利用都是 worker 的活。（查看任务目录或 shared/ 本地文件请直接用 Read / LS / Glob / Grep，切勿用 Bash）", PlannerProbeMessagePrefix, used, h.limit), nil
		}
	}
	if h.inner != nil {
		return h.inner.PreToolUse(ctx, name, input)
	}
	return false, "", nil
}

func (h plannerProbeHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	if h.inner != nil {
		h.inner.PostToolUse(ctx, name, input, result, isErr)
	}
}

func (h plannerProbeHooks) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	if h.inner != nil {
		return h.inner.Stop(ctx, messages)
	}
	return false, nil, ""
}
