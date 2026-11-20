package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
