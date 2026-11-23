// emp3r0r_roe_test.go —— deploy_emp3r0r 的 RoE 拦截测试。
// 仿 session_roe_test.go：strict 模式下越权目标应被拦截，warn 放行留痕。
package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/session"
	"github.com/Autumn-27/artex/stage"
	actool "github.com/Autumn-27/norma/tool"
)

// stubViaSession 是最小立足点会话：Exec 回显命令本身（哨兵检查据此通过）。
type stubViaSession struct {
	id int64
}

func (v *stubViaSession) ID() int64                  { return v.id }
func (v *stubViaSession) Kind() string               { return "http_php" }
func (v *stubViaSession) Test(context.Context) error { return nil }
func (v *stubViaSession) Exec(_ context.Context, cmd string, _ time.Duration) (string, string, error) {
	return cmd, "", nil
}
func (v *stubViaSession) ReadFile(context.Context, string) ([]byte, error) { return nil, nil }
func (v *stubViaSession) WriteFile(context.Context, string, []byte) error  { return nil }
func (v *stubViaSession) Close(context.Context) error                      { return nil }

// emp3r0rDeployFixture 在 roeFixture 之上补 emp3r0r 运行时、stage 与一条 via 会话。
func emp3r0rDeployFixture(t *testing.T, mode string, viaURL string) (*Server, *db.Task, int64) {
	t.Helper()
	pg, task, s := roeFixture(t, mode)
	s.sessReg = session.NewRegistry()
	s.sessStore = db.NewSessionStore(pg, []byte("roe-session-test-key"))
	dir := t.TempDir()
	st, err := stage.New(context.Background(), filepath.Join(dir, "stage"))
	if err != nil {
		t.Fatalf("stage.New: %v", err)
	}
	s.stage = st
	s.ctx = context.Background()

	// agent_binary 放一个真文件（PutFile 要读它）。
	bin := filepath.Join(dir, "agent")
	if err := os.WriteFile(bin, []byte("fake-agent"), 0o600); err != nil {
		t.Fatalf("agent fixture: %v", err)
	}
	client, err := session.NewCCClient(session.Emp3r0rConfig{
		Endpoint: "127.0.0.1:1", ServerIP: "172.16.254.1",
	})
	if err != nil {
		t.Fatalf("NewCCClient: %v", err)
	}
	s.emp3r0r = &emp3r0rRuntime{
		cfg:    config.Emp3r0r{Enabled: true, AgentBinary: bin, AgentWaitSec: 2},
		client: client,
		seen:   map[string]int64{},
	}
	sec, _ := json.Marshal(session.Secret{URL: viaURL})
	viaRec := &db.SessionRecord{
		Kind: "http_php", URL: viaURL, Secret: sec, Status: db.SessionAlive,
	}
	viaID, err := s.sessStore.Create(context.Background(), viaRec)
	if err != nil {
		t.Fatalf("via 落库: %v", err)
	}
	t.Cleanup(func() {
		// 共享测试库：清理本 fixture 的 session 行，不污染其他测试。
		_ = s.sessStore.Delete(context.Background(), viaID)
	})
	s.sessReg.Add(&stubViaSession{id: viaID})
	return s, task, viaID
}

func TestDeployEmp3r0rStrictBlocksOutOfScope(t *testing.T) {
	s, task, viaID := emp3r0rDeployFixture(t, "strict", "http://203.0.113.10:8080/shell.php")
	tool := s.deployEmp3r0rTool()
	in, _ := json.Marshal(map[string]any{"session_id": viaID})
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: task.ID})
	res, err := tool.Call(ctx, in, &actool.ToolContext{})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	text := res.Flatten()
	if !res.IsError {
		t.Fatalf("strict 越权应拦截: %s", text)
	}
	if !strings.Contains(text, "RoE") || !strings.Contains(text, "授权范围") {
		t.Fatalf("错误应说明 RoE 拦截: %s", text)
	}
	if !strings.Contains(text, "emp3r0r agent 部署目标") {
		t.Fatalf("错误应指明部署目标角色: %s", text)
	}
}

func TestDeployEmp3r0rWarnAllowsOutOfScope(t *testing.T) {
	s, task, viaID := emp3r0rDeployFixture(t, "warn", "http://203.0.113.10:8080/shell.php")
	tool := s.deployEmp3r0rTool()
	in, _ := json.Marshal(map[string]any{"session_id": viaID, "wait_seconds": 1})
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: task.ID})
	res, err := tool.Call(ctx, in, &actool.ToolContext{})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	text := res.Flatten()
	// warn 放行 → 越过 RoE 走到 cc 轮询（mock client 拨号失败 → 诚实错误）。
	if !res.IsError {
		t.Fatalf("无回连时应报错: %s", text)
	}
	if !strings.Contains(text, "RoE") {
		t.Fatalf("warn 模式应带 RoE 告警前缀: %s", text)
	}
	if strings.Contains(text, "授权范围检查") && !strings.Contains(text, "⚠") {
		t.Fatalf("warn 应是告警而非拒绝: %s", text)
	}
}

func TestDeployEmp3r0rInScopeAllowed(t *testing.T) {
	s, task, viaID := emp3r0rDeployFixture(t, "strict", "http://10.255.255.9:8080/shell.php")
	tool := s.deployEmp3r0rTool()
	in, _ := json.Marshal(map[string]any{"session_id": viaID, "wait_seconds": 1})
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: task.ID})
	res, err := tool.Call(ctx, in, &actool.ToolContext{})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	text := res.Flatten()
	// 范围内放行 → 不应出现 RoE 拦截字样；失败只可能是 cc 拨号。
	if strings.Contains(text, "授权范围") {
		t.Fatalf("范围内不应有 RoE 拦截: %s", text)
	}
	if !res.IsError {
		t.Fatalf("cc 不可达应报错: %s", text)
	}
}
