package server

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestTaskStatsHandlerPG(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	task, err := m.CreateTask("stats handler", "", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	other, err := m.CreateTask("stats other task", "", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, id := range []string{task.ID, other.ID} {
			_, _ = m.pg.Exec(`DELETE FROM llm_usage WHERE task_id=$1`, id)
			_, _ = m.pg.Exec(`DELETE FROM plan_rounds WHERE task_id=$1`, id)
			numericID, _ := strconv.ParseInt(id, 10, 64)
			_ = m.pg.DeleteTask(numericID)
		}
	})
	s := &Server{m: m, engine: NewEngine(m), jwtKey: []byte("task-stats-handler-test-signing-key")}
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	request := func(ctx context.Context, id string, authenticated bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/tasks/"+id+"/stats", nil).WithContext(ctx)
		if authenticated {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := request(t.Context(), task.ID, false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := request(t.Context(), "999999999999999", true); rec.Code != http.StatusNotFound {
		t.Fatalf("missing task status=%d body=%s", rec.Code, rec.Body.String())
	}
	decodeStats := func(id string) taskStatsResponse {
		t.Helper()
		rec := request(t.Context(), id, true)
		if rec.Code != http.StatusOK {
			t.Fatalf("stats status=%d body=%s", rec.Code, rec.Body.String())
		}
		var result taskStatsResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	empty := decodeStats(task.ID)
	if empty.IntentCounts == nil || len(empty.IntentCounts) != 0 || empty.PlanRounds.Count != 0 ||
		empty.PlanRounds.DurationMSSum != 0 || empty.PlanRounds.DurationMSAvg != 0 || empty.PlanRounds.LLMCalls != 0 ||
		len(empty.PlanRounds.Outcomes) != 3 || empty.LLMUsage.ByWorker == nil || len(empty.LLMUsage.ByWorker) != 0 ||
		empty.LLMUsage.WorkerCallsWithIntentID != 0 || empty.LLMUsage.WorkerCallsWithoutIntentID != 0 {
		t.Fatalf("unstable empty response: %+v", empty)
	}
	for _, state := range []string{"open", "open", "stopped", "done"} {
		if _, err := task.Store.AddNode("intent", map[string]any{"summary": "stats fixture"}, 1, state, "planner", nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := other.Store.AddNode("intent", map[string]any{"summary": "excluded"}, 1, "open", "planner", nil); err != nil {
		t.Fatal(err)
	}
	for i, outcome := range []string{"ok", "error", "met"} {
		if err := m.pg.InsertPlanRound(t.Context(), db.PlanRound{TaskID: task.ID, Round: int64(i + 1), StartedAt: time.Now(),
			DurationMS: int64((i + 1) * 100), LLMCalls: int64(i + 2), Outcome: outcome}); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.pg.InsertPlanRound(t.Context(), db.PlanRound{TaskID: other.ID, Round: 1, StartedAt: time.Now(), DurationMS: 9000, LLMCalls: 90, Outcome: "met"}); err != nil {
		t.Fatal(err)
	}
	for i, latency := range []int{10, 30, 50} {
		status := "ok"
		intentID := int64(i + 1)
		if i == 2 {
			status, intentID = "error", 0
		}
		if err := m.pg.InsertLLMUsage(&db.LLMUsage{TaskID: task.ID, Worker: "worker", IntentID: intentID,
			LatencyMs: latency, InputTokens: (i + 1) * 100, OutputTokens: (i + 1) * 10, CacheRead: (i + 1) * 5, CacheWrite: i + 1, Status: status}); err != nil {
			t.Fatal(err)
		}
	}
	for _, usage := range []*db.LLMUsage{
		{TaskID: task.ID, Worker: "planner", InputTokens: 7, LatencyMs: 100, Status: "ok"},
		{TaskID: task.ID, Status: "error"},
		{TaskID: other.ID, Worker: "worker", InputTokens: 9999, LatencyMs: 9000, Status: "error"},
	} {
		if err := m.pg.InsertLLMUsage(usage); err != nil {
			t.Fatal(err)
		}
	}
	got := decodeStats(task.ID)
	if len(got.IntentCounts) != 3 || got.IntentCounts["open"] != 2 || got.IntentCounts["stopped"] != 1 || got.IntentCounts["done"] != 1 {
		t.Fatalf("intent counts=%v", got.IntentCounts)
	}
	rounds := got.PlanRounds
	if rounds.Count != 3 || rounds.DurationMSSum != 600 || rounds.DurationMSAvg != 200 || rounds.LLMCalls != 9 ||
		rounds.Outcomes["ok"] != 1 || rounds.Outcomes["error"] != 1 || rounds.Outcomes["met"] != 1 {
		t.Fatalf("round summary=%+v", rounds)
	}
	usage := got.LLMUsage
	if len(usage.ByWorker) != 3 || usage.WorkerCallsWithIntentID != 2 || usage.WorkerCallsWithoutIntentID != 1 {
		t.Fatalf("usage summary=%+v", usage)
	}
	worker := usage.ByWorker[2]
	if worker.Worker != "worker" || worker.Calls != 3 || worker.Errors != 1 || worker.InputTokens != 600 || worker.OutputTokens != 60 ||
		worker.CacheReadTokens != 30 || worker.CacheWriteTokens != 6 || worker.LatencyP50MS != 30 || math.Abs(worker.LatencyP95MS-48) > 0.001 {
		t.Fatalf("worker summary=%+v", worker)
	}
	if planner := usage.ByWorker[1]; planner.Worker != "planner" || planner.Calls != 1 || planner.Errors != 0 || planner.InputTokens != 7 || planner.LatencyP50MS != 100 || planner.LatencyP95MS != 100 {
		t.Fatalf("planner summary=%+v", planner)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if rec := request(ctx, task.ID, true); rec.Code != http.StatusInternalServerError {
		t.Fatalf("cancelled query status=%d body=%s", rec.Code, rec.Body.String())
	}
}
