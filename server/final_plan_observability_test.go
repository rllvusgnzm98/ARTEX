package server

import (
	"errors"
	"strconv"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

func TestFinalPlannerRoundObservabilityPG(t *testing.T) {
	for _, outcome := range []string{"ok", "error", "skipped"} {
		t.Run(outcome, func(t *testing.T) {
			m, err := NewManager(t.TempDir(), "")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = m.Close() })
			task, err := m.CreateTask("final round instrumentation", "scripted goal", nil, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_, _ = m.pg.Exec(`DELETE FROM llm_usage WHERE task_id=$1`, task.ID)
				_, _ = m.pg.Exec(`DELETE FROM llm_records WHERE task_id=$1`, task.ID)
				_, _ = m.pg.Exec(`DELETE FROM plan_rounds WHERE task_id=$1`, task.ID)
				id, _ := strconv.ParseInt(task.ID, 10, 64)
				_ = m.pg.DeleteTask(id)
			})
			fake := &scriptedLLMProvider{events: []llm.StreamEvent{{Type: llm.SETextDelta, Text: "final judgment"}, {Type: llm.SEMessageDelta, StopReason: "end_turn"}}}
			if outcome == "error" {
				fake.events = nil
				fake.err = errors.New("scripted final failure")
			}
			prov := llmrec.Wrap(fake, m.pg, "local-final", "", "", "", nil)
			planner := agent.NewPlanner(prov, "local-final", m.dir, transcript.NewStore(t.TempDir()), 0, 0)
			worker := agent.NewWorker(prov, "local-final", m.dir, nil, 0, 0)
			e := NewEngine(m)
			e.SetAgentResolver(func(*Task) (*agent.Planner, *agent.Worker) { return planner, worker })
			if outcome == "skipped" {
				e.deleting.Store(task.ID, true)
			}
			task.NotifyGoal([]string{"final trigger"})
			e.runFinalPlannerRound(llmrec.WithTaskID(t.Context(), task.ID), task)
			var count int
			if err := m.pg.QueryRow(`SELECT count(*) FROM plan_rounds WHERE task_id=$1`, task.ID).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if outcome == "skipped" {
				if count != 0 {
					t.Fatalf("skipped rounds=%d", count)
				}
				return
			}
			var src, gotOutcome string
			var round, calls, usageCalls, invalid int64
			var triggers int
			if err := m.pg.QueryRow(`SELECT round,llm_calls,trigger_src,trigger_count,outcome FROM plan_rounds WHERE task_id=$1`, task.ID).Scan(&round, &calls, &src, &triggers, &gotOutcome); err != nil {
				t.Fatal(err)
			}
			if err := m.pg.QueryRow(`SELECT count(*),count(*) FILTER(WHERE plan_round IS DISTINCT FROM $2 OR worker_instance IS DISTINCT FROM 'planner') FROM llm_usage WHERE task_id=$1 AND worker='planner'`, task.ID, round).Scan(&usageCalls, &invalid); err != nil {
				t.Fatal(err)
			}
			if count != 1 || round != 1 || calls == 0 || calls != usageCalls || invalid != 0 || src != "final" || triggers != 1 || gotOutcome != outcome || e.ActiveLLMCalls(task.ID) != 0 {
				t.Fatalf("round=%d calls=%d usage=%d invalid=%d src=%s triggers=%d outcome=%s", round, calls, usageCalls, invalid, src, triggers, gotOutcome)
			}
		})
	}
}
