package server

import (
	"context"
	"encoding/json"
	"iter"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

func TestTriggerTaskRetroAndDedup(t *testing.T) {
	pg := openTestPG(t)
	row, err := pg.CreateTask("retro checkpoint fixture", "test manual and pause retro", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pg.DeleteTask(row.ID); err != nil {
			t.Error(err)
		}
	})
	store := pg.Exploration(row.ExplorationID)
	if _, err := store.AddNode(db.KindFinding, map[string]any{"name": "PrestaShop XSS", "vulnclass": "xss", "severity": "high"}, 0, "confirmed", "worker", nil); err != nil {
		t.Fatal(err)
	}

	taskID := strconv.FormatInt(row.ID, 10)
	fakeProv := &scriptedLLMProvider{
		events: []llm.StreamEvent{
			{Type: llm.SEMessageStart},
			{Type: llm.SETextDelta, Text: `[{"category":"web","scene":"异步管理员XSS验证","criteria":"先用OOB回传DOM","pivot":"改用sendBeacon单步完成"}]`},
			{Type: llm.SEMessageStop},
		},
	}
	s := &Server{
		m: &Manager{
			pg:    pg,
			tasks: map[string]*Task{taskID: {ID: taskID, ExpID: row.ExplorationID, Store: store, Goal: "test"}},
		},
		ctx:     t.Context(),
		llmProv: fakeProv,
	}

	req1 := httptest.NewRequest(http.MethodPost, "/api/tasks/"+taskID+"/retro", nil)
	req1.SetPathValue("id", taskID)
	rec1 := httptest.NewRecorder()
	s.triggerTaskRetro(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first retro status=%d body=%s", rec1.Code, rec1.Body.String())
	}
	var out1 struct {
		OK     bool `json:"ok"`
		Queued int  `json:"queued"`
	}
	if err := json.Unmarshal(rec1.Body.Bytes(), &out1); err != nil || !out1.OK || out1.Queued != 1 {
		t.Fatalf("unexpected first retro body: %s err=%v", rec1.Body.String(), err)
	}

	// Second call with identical distilled scene deduplicates cleanly.
	req2 := httptest.NewRequest(http.MethodPost, "/api/tasks/"+taskID+"/retro", nil)
	req2.SetPathValue("id", taskID)
	rec2 := httptest.NewRecorder()
	s.triggerTaskRetro(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("second retro status=%d body=%s", rec2.Code, rec2.Body.String())
	}
	var out2 struct {
		OK     bool `json:"ok"`
		Queued int  `json:"queued"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &out2); err != nil || !out2.OK || out2.Queued != 0 {
		t.Fatalf("expected deduplicated queued=0, got: %s err=%v", rec2.Body.String(), err)
	}

	// Below pause-retro threshold (1 finding, 0 rounds): maybeRunPauseRetro skips without calling LLM.
	prevCalls := fakeProv.calls
	s.maybeRunPauseRetro(taskID)
	if fakeProv.calls != prevCalls {
		t.Fatalf("maybeRunPauseRetro should skip below threshold, calls %d -> %d", prevCalls, fakeProv.calls)
	}

	// Bump rounds to 10 -> maybeRunPauseRetro runs once for this milestone and skips repeat.
	if _, err := pg.Exec(`UPDATE explorations SET round_no=10 WHERE id=$1`, row.ExplorationID); err != nil {
		t.Fatal(err)
	}
	s.maybeRunPauseRetro(taskID)
	if fakeProv.calls != prevCalls+1 {
		t.Fatalf("expected maybeRunPauseRetro to run at round_no=10, calls=%d", fakeProv.calls)
	}
	s.maybeRunPauseRetro(taskID)
	if fakeProv.calls != prevCalls+1 {
		t.Fatalf("expected maybeRunPauseRetro to skip duplicate milestone, calls=%d", fakeProv.calls)
	}
}

type retroFallbackProvider struct {
	calls     int
	prompts   []string
	failFirst error
	reply     string
}

func (p *retroFallbackProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return llm.Message{}, "", llm.Usage{}, nil
}

func (p *retroFallbackProvider) Stream(_ context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	p.calls++
	if len(req.Messages) > 0 {
		p.prompts = append(p.prompts, req.Messages[0].Text())
	}
	attempt := p.calls
	return func(yield func(llm.StreamEvent, error) bool) {
		if attempt == 1 && p.failFirst != nil {
			yield(llm.StreamEvent{}, p.failFirst)
			return
		}
		if !yield(llm.StreamEvent{Type: llm.SEMessageStart}, nil) {
			return
		}
		if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: p.reply}, nil) {
			return
		}
		yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}

func TestRetroTimeoutFallsBackToCompactInput(t *testing.T) {
	pg := openTestPG(t)
	row, err := pg.CreateTask("retro timeout fallback fixture", "test compact fallback", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(row.ID) })
	store := pg.Exploration(row.ExplorationID)
	if _, err := store.AddNode(db.KindFinding, map[string]any{"name": "WebLogic CVE-2017-10271", "vulnclass": "rce", "severity": "critical"}, 0, "confirmed", "worker", nil); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		if _, err := store.AddNode(db.KindFact, map[string]any{"summary": "中文长事实段落" + strings.Repeat("内网横向记录", 40)}, 0, "confirmed", "worker", nil); err != nil {
			t.Fatal(err)
		}
	}

	prevPrimary, prevCompact := retroCallTimeout, retroCompactCallTimeout
	retroCallTimeout = 2 * time.Second
	retroCompactCallTimeout = 2 * time.Second
	t.Cleanup(func() {
		retroCallTimeout = prevPrimary
		retroCompactCallTimeout = prevCompact
	})

	taskID := strconv.FormatInt(row.ID, 10)
	prov := &retroFallbackProvider{
		failFirst: context.DeadlineExceeded,
		reply:     `[{"category":"pivot","scene":"多跳跳板超时前发射慢利用","criteria":"撤退清单留有后台尾日志","pivot":"接班单先读尾日志再复验避免重发"}]`,
	}
	s := &Server{
		m: &Manager{
			pg:    pg,
			tasks: map[string]*Task{taskID: {ID: taskID, ExpID: row.ExplorationID, Store: store, Goal: "拿域控 flag"}},
		},
		ctx:     t.Context(),
		llmProv: prov,
	}

	n, err := s.runRetroWithResult(t.Context(), taskID)
	if err != nil {
		t.Fatalf("runRetroWithResult fallback failed: %v", err)
	}
	if n != 1 || prov.calls != 2 {
		t.Fatalf("expected 1 entry across 2 attempts (primary timeout + compact retry), got n=%d calls=%d", n, prov.calls)
	}
	if len(prov.prompts[1]) >= len(prov.prompts[0]) || len(prov.prompts[1]) > 8064 {
		t.Fatalf("compact retry prompt must be strictly smaller and bounded: full=%d compact=%d", len(prov.prompts[0]), len(prov.prompts[1]))
	}
	if !utf8.ValidString(prov.prompts[0]) || !utf8.ValidString(prov.prompts[1]) {
		t.Fatal("retro prompts must remain valid UTF-8 after byte budgeting")
	}
}
