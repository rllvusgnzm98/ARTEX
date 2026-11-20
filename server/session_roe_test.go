package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/session"
	actool "github.com/Autumn-27/norma/tool"
)

func TestRoERegisterSessionStrictOutOfScope(t *testing.T) {
	_, task, s := roeFixture(t, "strict")
	var hits atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "not-a-shell", http.StatusNotFound)
	}))
	t.Cleanup(origin.Close)

	s.sessReg = session.NewRegistry()
	s.sessStore = db.NewSessionStore(s.m.pg, []byte("roe-session-test-key"))
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	ctx = agent.WithRunInfo(ctx, agent.RunInfo{TaskID: task.ID})

	tool := s.registerSessionTool()
	in, _ := json.Marshal(map[string]any{
		"url":  "http://10.255.0.9/s.php",
		"lang": "php",
	})
	res, err := tool.Call(ctx, in, &actool.ToolContext{})
	if err != nil {
		t.Fatalf("register_session: %v", err)
	}
	text := res.Flatten()
	if !res.IsError || !strings.Contains(text, "RoE 授权范围检查") || !strings.Contains(text, "立足点目标 10.255.0.9") {
		t.Fatalf("strict 越界应拒绝: %s", text)
	}
	if strings.Contains(text, "探测失败") {
		t.Fatalf("越界不得进入探测: %s", text)
	}
	if hits.Load() != 0 {
		t.Fatalf("越界请求打到了本地探针 %d 次", hits.Load())
	}
}

func TestRoERegisterSessionInScopeProbes(t *testing.T) {
	_, task, s := roeFixture(t, "strict")
	var hits atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "not-a-shell", http.StatusNotFound)
	}))
	t.Cleanup(origin.Close)
	if _, err := s.m.pg.Assets().AddAgentScope(task.ID, "ip", "127.0.0.1", "loopback foothold", "manual"); err != nil {
		t.Fatalf("AddAgentScope: %v", err)
	}

	s.sessReg = session.NewRegistry()
	s.sessStore = db.NewSessionStore(s.m.pg, []byte("roe-session-test-key"))
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	ctx = agent.WithRunInfo(ctx, agent.RunInfo{TaskID: task.ID})

	tool := s.registerSessionTool()
	in, _ := json.Marshal(map[string]any{"url": origin.URL + "/s.php", "lang": "php"})
	res, err := tool.Call(ctx, in, &actool.ToolContext{})
	if err != nil {
		t.Fatalf("register_session: %v", err)
	}
	text := res.Flatten()
	if !res.IsError || !strings.Contains(text, "探测失败") {
		t.Fatalf("范围内应放行并进入探测: %s", text)
	}
	if strings.Contains(text, "RoE 授权范围检查") {
		t.Fatalf("范围内不应被 RoE 拒绝: %s", text)
	}
	if hits.Load() == 0 {
		t.Fatal("范围内探测没有打到本地探针")
	}
}

func TestRoERegisterSessionWarnProbeFailureKeepsWarning(t *testing.T) {
	pg, task, s := roeFixture(t, "warn")
	// 127.0.0.1 被 ScopeMatcher.AllowLocal 当成范围内。用任务范围外的地址，探针才会在告警之后失败。
	const host = "10.255.0.9"

	id := strconv.FormatInt(task.ID, 10)
	s.m.tasks = map[string]*Task{
		id: {ID: id, Store: pg.Exploration(task.ExplorationID)},
	}
	s.sessReg = session.NewRegistry()
	s.sessStore = db.NewSessionStore(s.m.pg, []byte("roe-session-test-key"))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ctx = agent.WithRunInfo(ctx, agent.RunInfo{TaskID: task.ID})

	tool := s.registerSessionTool()
	in, _ := json.Marshal(map[string]any{"url": "http://" + host + ":9/s.php", "lang": "php"})
	res, err := tool.Call(ctx, in, &actool.ToolContext{})
	if err != nil {
		t.Fatalf("register_session: %v", err)
	}
	text := res.Flatten()
	if !res.IsError || !strings.Contains(text, "探测失败") {
		t.Fatalf("探针失败应返回错误: %s", text)
	}
	if !strings.Contains(text, "⚠") || !strings.Contains(text, "RoE 授权范围检查") || !strings.Contains(text, "立足点目标 "+host) {
		t.Fatalf("探针失败仍应带上越界告警: %s", text)
	}
	if strings.Index(text, "RoE 授权范围检查") > strings.Index(text, "探测失败") {
		t.Fatalf("告警应出现在探测失败之前: %s", text)
	}
	var summary string
	err = pg.QueryRow(`SELECT COALESCE(summary,'') FROM activity WHERE exploration_id=$1 AND tool='roe' ORDER BY id DESC LIMIT 1`, task.ExplorationID).Scan(&summary)
	if err != nil {
		t.Fatalf("探针失败后 activity 里没有 RoE 告警: %v", err)
	}
	if !strings.Contains(summary, "⚠") || !strings.Contains(summary, host) {
		t.Fatalf("activity = %q", summary)
	}
}
