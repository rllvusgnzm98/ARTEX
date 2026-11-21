package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func retentionStore(t *testing.T) (*db.DB, *db.ExplorationStore) {
	t.Helper()
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("retention regression", "retain results", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := d.DeleteTask(task.ID); err != nil {
			t.Error(err)
		}
	})
	return d, d.Exploration(task.ExplorationID)
}

func TestWorkerOutputLatestActivity(t *testing.T) {
	for _, tc := range []struct{ name, kind string }{{"result", "result"}, {"text_only", "text"}, {"empty", ""}} {
		t.Run(tc.name, func(t *testing.T) {
			d, es := retentionStore(t)
			id, err := es.AddIntent(map[string]any{"summary": "output"}, 0, nil, "worker")
			if err != nil {
				t.Fatal(err)
			}
			want := "latest output"
			if tc.kind != "" {
				if _, err := es.AppendActivity(db.Activity{NodeID: &id, Kind: "text", Summary: "early", Detail: "early"}); err != nil {
					t.Fatal(err)
				}
				if _, err := d.Exec(`INSERT INTO activity (exploration_id,node_id,kind,summary) SELECT $1,$2,'tool_result','filler' FROM generate_series(1,1000)`, es.ID(), id); err != nil {
					t.Fatal(err)
				}
				if _, err := es.AppendActivity(db.Activity{NodeID: &id, Kind: tc.kind, Summary: want, Detail: want}); err != nil {
					t.Fatal(err)
				}
				if tc.kind == "result" {
					if _, err := es.AppendActivity(db.Activity{NodeID: &id, Kind: "text", Summary: "later text", Detail: "later text"}); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				want = "(该 work 尚无输出记录)"
			}
			if got := workerOutput(es, id); got != want {
				t.Errorf("workerOutput=%q want %q", got, want)
			}
			ts := NewToolSet(es, "planner")
			res, err := ts.getWorkerOutput().Call(context.Background(), json.RawMessage(fmt.Sprintf(`{"intent_id":%d}`, id)), nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.kind == "" {
				if !strings.Contains(res.Flatten(), "尚无任何输出") {
					t.Errorf("empty output=%s", res.Flatten())
				}
			} else {
				var got map[string]any
				if err := json.Unmarshal([]byte(res.Flatten()), &got); err != nil {
					t.Fatal(err)
				}
				if got["final_text"] != want {
					t.Errorf("get_worker_output=%v want %q", got, want)
				}
			}
			var sourceTaskID int64
			if err := d.QueryRow(`SELECT id FROM tasks WHERE exploration_id=$1`, es.ID()).Scan(&sourceTaskID); err != nil {
				t.Fatal(err)
			}
			child, err := d.CreateTaskWithOptions("consumer", "read source output", db.TaskCreateOptions{SourceTaskIDs: []int64{sourceTaskID}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := d.DeleteTask(child.ID); err != nil {
					t.Error(err)
				}
			})
			childStore := d.Exploration(child.ExplorationID)
			if got, err := childStore.LatestWorkerOutputWithSources(id); err != nil || got != nil {
				t.Fatalf("live inherited output=%v err=%v", got, err)
			}
			if err := es.SetIntentState(id, "done"); err != nil {
				t.Fatal(err)
			}
			inherited, err := NewToolSet(childStore, "planner").getWorkerOutput().Call(context.Background(), json.RawMessage(fmt.Sprintf(`{"intent_id":%d}`, id)), nil)
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			if err := json.Unmarshal([]byte(inherited.Flatten()), &got); err != nil {
				t.Fatal(err)
			}
			if got["inherited"] != true || got["source_task_id"] != float64(sourceTaskID) {
				t.Errorf("inherited metadata=%v", got)
			}
			if tc.kind != "" && got["final_text"] != want {
				t.Errorf("inherited output=%v want %q", got, want)
			}
		})
	}
	t.Run("query_error", func(t *testing.T) {
		d := testDB(t)
		t.Cleanup(func() { d.Close() })
		es := d.Exploration(1)
		if err := d.Close(); err != nil {
			t.Fatal(err)
		}
		if got := workerOutput(es, 1); got != "(取输出失败)" {
			t.Errorf("query error output=%q", got)
		}
		if _, err := es.LatestWorkerOutput(1); err == nil {
			t.Error("expected query error")
		}
	})
}

func TestGraphOverviewRunningBeyondRecentWindow(t *testing.T) {
	d, es := retentionStore(t)
	id, err := es.AddNode(db.KindIntent, map[string]any{"summary": "still running"}, 0, "running", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO exploration_nodes (exploration_id,kind,payload,state,origin) SELECT $1,'intent','{}'::jsonb,'done','worker' FROM generate_series(1,301)`, es.ID()); err != nil {
		t.Fatal(err)
	}
	out := NewToolSet(es, "planner").graphOverviewData()
	running := out["running_intents"].([]map[string]any)
	if len(running) != 1 || running[0]["id"] != id {
		t.Errorf("running_intents=%v want intent %d", running, id)
	}
	if out["running_intents_total"] != 1 {
		t.Errorf("running_intents_total=%v want 1", out["running_intents_total"])
	}
	fallback := &graphSnapshot{ts: es, loaded: true, err: fmt.Errorf("snapshot unavailable")}
	fallbackRunning, err := fallback.runningIntents()
	if err != nil || len(fallbackRunning) != 1 || fallbackRunning[0].ID != id {
		t.Errorf("fallback running=%v err=%v", fallbackRunning, err)
	}
	if out["done_intents_total"] != 301 {
		t.Errorf("done_intents_total=%v want 301", out["done_intents_total"])
	}
}

func TestGraphOverviewTrueTotalsBeyondCaps(t *testing.T) {
	d, es := retentionStore(t)
	for _, kind := range []string{db.KindFact, db.KindFinding, db.KindGoal, db.KindHint} {
		if _, err := d.Exec(`INSERT INTO exploration_nodes (exploration_id,kind,payload,state,origin) SELECT $1,$2,'{}'::jsonb,CASE $2 WHEN 'goal' THEN 'open' WHEN 'hint' THEN 'active' ELSE 'confirmed' END,'worker' FROM generate_series(1,1001)`, es.ID(), kind); err != nil {
			t.Fatal(err)
		}
	}
	out := NewToolSet(es, "planner").graphOverviewData()
	for key, kind := range map[string]string{"facts": db.KindFact, "facts_total": db.KindFact, "findings_total": db.KindFinding, "goals_total": db.KindGoal, "hints_total": db.KindHint} {
		var want int
		if err := d.QueryRow(`SELECT COUNT(*) FROM exploration_nodes WHERE exploration_id=$1 AND kind=$2`, es.ID(), kind).Scan(&want); err != nil {
			t.Fatal(err)
		}
		if out[key] != want {
			t.Errorf("%s=%v want %d", key, out[key], want)
		}
	}
	for key, cap := range map[string]int{"finding_list": 10, "recent_facts": 20, "goals": 100, "hints": 50} {
		if got := len(out[key].([]map[string]any)); got != cap {
			t.Errorf("%s len=%d want cap %d", key, got, cap)
		}
	}
	fallback := &graphSnapshot{ts: es, loaded: true, err: fmt.Errorf("snapshot unavailable")}
	got := NewToolSet(es, "planner").graphOverviewDataFrom(fallback)
	for _, key := range []string{"facts", "facts_total", "findings_total", "goals_total", "hints_total", "running_intents_total"} {
		if got[key] != out[key] {
			t.Errorf("fallback %s=%v want %v", key, got[key], out[key])
		}
	}
}
