package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

func TestNeedsCampaignOrchestration(t *testing.T) {
	t.Parallel()
	cases := []struct {
		goal string
		want bool
	}{
		{"", false},
		{"test single target example.com", false},
		{"对 https://app.example.com 做渗透测试", false},
		{"TSec Benchmark 跑分任务：先对 10.0.100.58 做 VPN 联通预检，再 GET /openapi/v1/challenges", true},
		{"评估多个资产：http://10.0.0.1 http://10.0.0.2 http://10.0.0.3", true},
	}
	for _, tc := range cases {
		if got := NeedsCampaignOrchestration(tc.goal); got != tc.want {
			t.Errorf("NeedsCampaignOrchestration(%q)=%v want %v", tc.goal, got, tc.want)
		}
	}
}

func TestEngineCampaignKickoffRunsBeforePlanner(t *testing.T) {
	t.Setenv("ARTEX_SKILL_DIR", t.TempDir())
	pg := openTestPG(t)
	m := &Manager{pg: pg, dir: t.TempDir(), tasks: map[string]*Task{}}
	goal := "TSec Benchmark 跑分任务：GET /openapi/v1/challenges 并开启靶场容器"
	row, err := pg.CreateTask("campaign-kickoff", goal, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = pg.DeleteTask(row.ID)
	})
	store := pg.Exploration(row.ExplorationID)
	if _, err := store.AddGoal(map[string]any{"summary": "获取全部题目 flag"}, "test"); err != nil {
		t.Fatal(err)
	}
	task := &Task{
		ID:     strconv.FormatInt(row.ID, 10),
		ExpID:  row.ExplorationID,
		Goal:   goal,
		Status: "running",
		Store:  store,
		Guard:  guard.New(),
		notify: make(chan struct{}, 1),
	}
	m.tasks[task.ID] = task

	var order []string
	var orderMu sync.Mutex
	record := func(step string) {
		orderMu.Lock()
		order = append(order, step)
		orderMu.Unlock()
	}

	kickoffDone := make(chan struct{})
	plannerCalled := make(chan struct{}, 1)
	prov := retestProvider{complete: func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		record("planner")
		select {
		case plannerCalled <- struct{}{}:
		default:
		}
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("planned")}}, "end_turn", llm.Usage{}, nil
	}}
	pl := agent.NewPlanner(prov, "test", m.dir, nil, 0, 1)
	pl.SetNonStreaming(func() bool { return true })
	wk := agent.NewWorker(prov, "test", m.dir, nil, 0, 1)
	wk.SetNonStreaming(func() bool { return true })

	e := NewEngine(m)
	e.debounce = 10 * time.Millisecond
	e.SetAuthoritativeAgentResolver(func(*Task) (*agent.Planner, *agent.Worker) { return pl, wk })
	e.SetCampaignOrchestrator(
		func(tk *Task) bool { return NeedsCampaignOrchestration(tk.Goal) },
		func(ctx context.Context, tk *Task, trigger string) bool {
			record("campaign:" + trigger)
			if trigger == "kickoff" {
				close(kickoffDone)
			}
			return true
		},
	)

	ctx, cancel := context.WithCancel(t.Context())
	e.Run(ctx, task)
	t.Cleanup(func() {
		cancel()
		e.StopTask(task.ID)
	})

	select {
	case <-kickoffDone:
	case <-time.After(3 * time.Second):
		t.Fatal("kickoff patrol did not run")
	}
	select {
	case <-plannerCalled:
	case <-time.After(3 * time.Second):
		t.Fatal("planner did not wake after kickoff")
	}

	orderMu.Lock()
	defer orderMu.Unlock()
	if len(order) < 2 || order[0] != "campaign:kickoff" || order[1] != "planner" {
		t.Fatalf("unexpected execution order: %v, want [campaign:kickoff planner ...]", order)
	}
}

func TestHumanChatPreemptsAutoCampaignPatrolWithout409(t *testing.T) {
	pg := openTestPG(t)
	m := &Manager{pg: pg, assets: pg.Assets(), dir: t.TempDir(), tasks: map[string]*Task{}}
	row, err := pg.CreateTask("preempt-test", "campaign goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = pg.DeleteTask(row.ID)
	})
	store := pg.Exploration(row.ExplorationID)
	task := &Task{
		ID:     strconv.FormatInt(row.ID, 10),
		ExpID:  row.ExplorationID,
		Goal:   "campaign goal",
		Status: "running",
		Store:  store,
		notify: make(chan struct{}, 1),
	}
	m.tasks[task.ID] = task

	s := &Server{
		m:          m,
		engine:     NewEngine(m),
		ctx:        context.Background(),
		chatBusy:   map[string]bool{},
		chatAuto:   map[string]bool{},
		chatDone:   map[string]chan struct{}{},
		chatCancel: map[string]context.CancelCauseFunc{},
	}

	// Simulate an active background auto-patrol holding the task chat slot.
	patrolCtx, patrolCancel := context.WithCancelCause(s.ctx)
	patrolDone := make(chan struct{})
	s.chatBusy[task.ID] = true
	s.chatAuto[task.ID] = true
	s.chatCancel[task.ID] = patrolCancel
	s.chatDone[task.ID] = patrolDone
	var patrolAborted atomic.Bool
	go func() {
		<-patrolCtx.Done()
		patrolAborted.Store(true)
		// Simulate finishTaskChat cleaning up once Patrol exits.
		s.chatMu.Lock()
		delete(s.chatBusy, task.ID)
		delete(s.chatAuto, task.ID)
		delete(s.chatCancel, task.ID)
		delete(s.chatDone, task.ID)
		s.chatMu.Unlock()
		close(patrolDone)
	}()

	body, _ := json.Marshal(map[string]string{"message": "优先打 b-02"})
	req := httptest.NewRequest(http.MethodPost, "/api/tasks/chat?task="+task.ID, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.chat(rec, req)

	if rec.Code == http.StatusConflict {
		t.Fatalf("human chat during auto-patrol returned 409 Conflict: %s", rec.Body.String())
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !patrolAborted.Load() {
		t.Fatal("background auto-patrol was not cancelled by human chat")
	}
}

func TestWorkerWAF403SanitizesTailOnceAndSetsBlockedReason(t *testing.T) {
	pg := openTestPG(t)
	row, err := pg.CreateTask("waf-test", "target", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = pg.DeleteTask(row.ID)
	})
	store := pg.Exploration(row.ExplorationID)
	iid, err := store.AddIntent(map[string]any{"summary": "test c-03"}, 0, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntentState(iid, "running"); err != nil {
		t.Fatal(err)
	}
	intent, err := store.GetNode(iid)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	txDir := dir + "/transcripts"
	tx := transcript.NewStore(txDir)

	var calls atomic.Int32
	wafErr := errors.New("openai: status 403: <!DOCTYPE html><title>Attention Required! | Cloudflare</title>")
	prov := retestProvider{complete: func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		n := calls.Add(1)
		if n == 1 {
			input, _ := json.Marshal(map[string]string{
				"file_path": "poc.py",
				"content":   "CVE-2025-55182 React2Shell __proto__ " + "xxxxxxxxxx",
			})
			return llm.Message{
				Role:    llm.RoleAssistant,
				Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "t1", Name: "Write", Input: input}},
			}, "tool_use", llm.Usage{}, nil
		}
		return llm.Message{}, "", llm.Usage{}, wafErr
	}}

	wk := agent.NewWorker(prov, "test", dir, tx, 128000, 10)
	wk.SetNonStreaming(func() bool { return true })
	task := &Task{
		ID:     strconv.FormatInt(row.ID, 10),
		ExpID:  row.ExplorationID,
		Store:  store,
		Guard:  guard.New(),
		notify: make(chan struct{}, 1),
	}
	e := NewEngine(&Manager{})
	e.runIntent(t.Context(), task, "work#1", wk, intent, "", "")

	// Expected calls:
	// Call 1: Write tool_use
	// Call 2: WAF 403 on initial run
	// SanitizeTranscriptTailForWAF scrubs tail -> single retry Call 3 -> returns WAF 403 -> stops (NO 2x retry!)
	if got := calls.Load(); got != 3 {
		t.Fatalf("LLM calls=%d, want 3 (no blind retries on WAF 403)", got)
	}
	updated, err := store.GetNode(iid)
	if err != nil {
		t.Fatal(err)
	}
	if updated.State != "blocked" || updated.BlockedReason != db.IntentBlockedGatewayWAF {
		t.Fatalf("intent state=%q blocked_reason=%q, want blocked / %q", updated.State, updated.BlockedReason, db.IntentBlockedGatewayWAF)
	}
}
