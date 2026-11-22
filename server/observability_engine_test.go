package server

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

type observabilityEngineProvider struct {
	mu           sync.Mutex
	plannerCalls int
	workerCalls  map[string]int
	victim       int64
	started      chan struct{}
	roundTwo     chan struct{}
	task         *Task
	pg           *db.DB
}

func (p *observabilityEngineProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	panic("test uses non-streaming injected provider")
}

func (p *observabilityEngineProvider) Complete(ctx context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	session := transcript.SessionIDFrom(ctx)
	inputTokens := 20
	text := func() (llm.Message, string, llm.Usage, error) {
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("scripted work complete")}}, "end_turn", llm.Usage{InputTokens: inputTokens, OutputTokens: 2}, nil
	}
	tool := func(name, input string) (llm.Message, string, llm.Usage, error) {
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: fmt.Sprintf("%s-%d", session, time.Now().UnixNano()), Name: name, Input: json.RawMessage(input)}}}, "tool_use", llm.Usage{InputTokens: inputTokens, OutputTokens: 4}, nil
	}
	if strings.HasSuffix(session, "-planner") {
		p.mu.Lock()
		p.plannerCalls++
		call, victim := p.plannerCalls, p.victim
		p.mu.Unlock()
		switch call {
		case 1:
			return tool("add_intent", `{"intents":[{"summary":"script A"},{"summary":"script B"},{"summary":"script C"},{"summary":""}]}`)
		case 2:
			select {
			case <-p.started:
			case <-ctx.Done():
				return llm.Message{}, "", llm.Usage{}, ctx.Err()
			}
		case 3:
			close(p.roundTwo)
			return tool("kill_work", fmt.Sprintf(`{"intent_id":%d}`, victim))
		case 4:
			// Other workers finish while this planning round is still active.
			for {
				var done int
				if err := p.pg.QueryRowContext(ctx, `SELECT count(*) FROM exploration_nodes WHERE exploration_id=$1 AND kind='intent' AND state='done'`, p.task.Store.ID()).Scan(&done); err != nil {
					return llm.Message{}, "", llm.Usage{}, err
				}
				if done == 2 {
					break
				}
				select {
				case <-time.After(10 * time.Millisecond):
				case <-ctx.Done():
					return llm.Message{}, "", llm.Usage{}, ctx.Err()
				}
			}
			return tool("add_intent", `{"summary":"script replacement"}`)
		}
		return text()
	}
	p.mu.Lock()
	turn := p.workerCalls[session]
	p.workerCalls[session]++
	id, _ := strconv.ParseInt(session[strings.LastIndex(session, "-i")+2:], 10, 64)
	inputTokens = int(id)
	if turn == 0 {
		if p.victim == 0 {
			p.victim = id
		}
		if len(p.workerCalls) == 3 {
			close(p.started)
		}
	}
	victim := p.victim
	p.mu.Unlock()
	select {
	case <-time.After(25 * time.Millisecond):
	case <-ctx.Done():
		return llm.Message{}, "", llm.Usage{}, ctx.Err()
	}
	if turn < 2 {
		return tool("Bash", fmt.Sprintf(`{"command":"printf 'turn %d'"}`, turn))
	}
	if id == victim {
		<-ctx.Done()
		return llm.Message{}, "", llm.Usage{InputTokens: inputTokens}, ctx.Err()
	}
	select {
	case <-p.roundTwo:
	case <-ctx.Done():
		return llm.Message{}, "", llm.Usage{}, ctx.Err()
	}
	return text()
}

func TestObservabilityEngineConcurrentPG(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	oldWorkers := m.Workers()
	if err := m.SetWorkers(3); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.SetWorkers(oldWorkers) })
	task, err := m.CreateTask("concurrent observability", "exercise scripted local workers", nil, 0, 0)
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
	if err := m.pg.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	if _, err := task.Store.AddGoal(map[string]any{"summary": "scripted local concurrency"}, "test"); err != nil {
		t.Fatal(err)
	}
	if err := m.SetTaskStatus(task.ID, "running"); err != nil {
		t.Fatal(err)
	}
	p := &observabilityEngineProvider{workerCalls: map[string]int{}, started: make(chan struct{}), roundTwo: make(chan struct{}), task: task, pg: m.pg}
	prov := llmrec.Wrap(p, m.pg, "local-script", "", "", "", nil)
	tx := transcript.NewStore(t.TempDir())
	planner := agent.NewPlanner(prov, "local-script", m.dir, tx, 0, 0)
	worker := agent.NewWorker(prov, "local-script", m.dir, tx, 0, 0)
	planner.SetNonStreaming(func() bool { return true })
	worker.SetNonStreaming(func() bool { return true })
	e := NewEngine(m)
	planner.SetKillWork(e.killWorkAttributed)
	e.SetAgentResolver(func(*Task) (*agent.Planner, *agent.Worker) { return planner, worker })
	ctx, cancel := context.WithTimeout(llmrec.WithTaskID(t.Context(), task.ID), 25*time.Second)
	defer cancel()
	t.Cleanup(func() { cancel(); e.StopTask(task.ID) })
	e.Run(ctx, task)
	select {
	case <-p.started:
	case <-ctx.Done():
		t.Fatal("three workers did not overlap", ctx.Err())
	}
	task.Notify()
	for {
		var finished, cancelled int
		if err := m.pg.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE state='stopped') FROM exploration_nodes WHERE exploration_id=$1 AND kind='intent' AND state IN ('done','stopped')`, task.Store.ID()).Scan(&finished, &cancelled); err != nil {
			t.Fatal(err)
		}
		if finished == 4 && cancelled == 1 {
			break
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal("workers did not settle", ctx.Err())
		}
	}
	cancel()
	e.StopTask(task.ID)
	rows, err := m.pg.Query(`SELECT round,llm_calls,intents_added,intents_cancelled FROM plan_rounds WHERE task_id=$1 ORDER BY round`, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var rounds [][4]int64
	for rows.Next() {
		var r [4]int64
		if err := rows.Scan(&r[0], &r[1], &r[2], &r[3]); err != nil {
			t.Fatal(err)
		}
		rounds = append(rounds, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(rounds) < 2 {
		t.Fatalf("rounds=%v", rounds)
	}
	for _, r := range rounds {
		wantAdded, wantCancelled := int64(0), int64(0)
		if r[0] == 1 {
			wantAdded = 3
		}
		if r[0] == 2 {
			wantAdded, wantCancelled = 1, 1
		}
		var calls int64
		if err := m.pg.QueryRow(`SELECT count(*) FROM llm_usage WHERE task_id=$1 AND worker='planner' AND plan_round=$2`, task.ID, r[0]).Scan(&calls); err != nil {
			t.Fatal(err)
		}
		if r[1] != calls || r[2] != wantAdded || r[3] != wantCancelled {
			t.Fatalf("round=%v usage calls=%d want actions=%d/%d", r, calls, wantAdded, wantCancelled)
		}
	}
	t.Logf("plan_rounds [round,llm_calls,intents_added,intents_cancelled]: %v", rounds)
	var invalid, workerRows, workerInstances int
	if err := m.pg.QueryRow(`SELECT count(*) FILTER(WHERE u.intent_id IS NULL OR u.worker_instance NOT LIKE 'work#%' OR u.worker_instance IS NULL OR u.input_tokens<>u.intent_id OR u.exploration_id<>$2),count(*),count(DISTINCT worker_instance) FROM llm_usage u WHERE task_id=$1 AND worker='worker'`, task.ID, task.Store.ID()).Scan(&invalid, &workerRows, &workerInstances); err != nil {
		t.Fatal(err)
	}
	if invalid != 0 || workerRows < 9 || workerInstances != 3 {
		t.Fatalf("invalid=%d worker rows=%d instances=%d", invalid, workerRows, workerInstances)
	}
	if err := m.pg.QueryRow(`SELECT count(*) FROM llm_usage u LEFT JOIN plan_rounds r ON r.task_id=u.task_id AND r.round=u.plan_round WHERE u.task_id=$1 AND u.worker='planner' AND (r.round IS NULL OR u.worker_instance<>'planner')`, task.ID).Scan(&invalid); err != nil || invalid != 0 {
		t.Fatalf("unattributed planner rows=%d err=%v", invalid, err)
	}
	s := &Server{m: m, engine: e, jwtKey: []byte("local-script-test-signing-key")}
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/tasks/"+task.ID+"/stats", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("stats status=%d body=%s", rec.Code, rec.Body.String())
	}
	var stats taskStatsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	if stats.IntentCounts["done"] != 3 || stats.IntentCounts["stopped"] != 1 || stats.PlanRounds.Count != int64(len(rounds)) || stats.LLMUsage.WorkerCallsWithIntentID != int64(workerRows) || stats.LLMUsage.WorkerCallsWithoutIntentID != 0 {
		t.Fatalf("stats mismatch: %s", rec.Body.String())
	}
	var totalCalls int64
	for _, r := range rounds {
		totalCalls += r[1]
	}
	if stats.PlanRounds.LLMCalls != totalCalls {
		t.Fatalf("stats calls=%d want %d", stats.PlanRounds.LLMCalls, totalCalls)
	}
	t.Logf("stats JSON: %s", rec.Body.String())
}
