package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/stage"
	actool "github.com/Autumn-27/norma/tool"
)

func fenceServer(t *testing.T) (*Server, string) {
	t.Helper()
	dataDir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	st, err := stage.New(ctx, filepath.Join(dataDir, "stage"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	s := &Server{m: &Manager{dir: dataDir, tasks: map[string]*Task{}}, ctx: ctx, stage: st}
	st.OnEvent = s.recordStageEvent
	return s, dataDir
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestResolveTaskWorkspaceFileAllowsInside(t *testing.T) {
	s, dataDir := fenceServer(t)
	inside := filepath.Join(dataDir, "tasks", "42", "payload.bin")
	mustWrite(t, inside, "hello")

	got, err := s.resolveTaskWorkspaceFile("42", inside)
	if err != nil {
		t.Fatalf("绝对路径应放行: %v", err)
	}
	real, err := filepath.EvalSymlinks(inside)
	if err != nil {
		t.Fatal(err)
	}
	if got != real {
		t.Fatalf("got %s want %s", got, real)
	}

	rel, err := s.resolveTaskWorkspaceFile("42", "payload.bin")
	if err != nil || rel != real {
		t.Fatalf("相对路径应放行: %s %v", rel, err)
	}
}

func TestResolveTaskWorkspaceFileRejectsEscapeAndMissing(t *testing.T) {
	s, dataDir := fenceServer(t)
	ws := filepath.Join(dataDir, "tasks", "42")
	mustWrite(t, filepath.Join(ws, "ok.bin"), "ok")
	outside := filepath.Join(dataDir, "outside.bin")
	mustWrite(t, outside, "secret")
	other := filepath.Join(dataDir, "tasks", "99", "other.bin")
	mustWrite(t, other, "other")

	// 工作区外
	if _, err := s.resolveTaskWorkspaceFile("42", outside); err == nil {
		t.Fatal("工作区外路径应拒绝")
	}
	// ../ 逃出
	if _, err := s.resolveTaskWorkspaceFile("42", filepath.Join("..", "outside.bin")); err == nil {
		t.Fatal("../ 应拒绝")
	}
	if _, err := s.resolveTaskWorkspaceFile("42", filepath.Join(ws, "..", "99", "other.bin")); err == nil {
		t.Fatal("经由 .. 进入其它任务目录应拒绝")
	}
	// 不存在
	if _, err := s.resolveTaskWorkspaceFile("42", filepath.Join(ws, "missing.bin")); err == nil {
		t.Fatal("不存在的文件应拒绝")
	}
	// 指向工作区外的符号链接
	link := filepath.Join(ws, "escape")
	if err := os.Symlink(outside, link); err != nil {
		// Windows 默认策略下创建符号链接需要额外特权；本用例在无权限环境跳过，
		// 其余越界断言仍然执行。
		t.Logf("跳过符号链接越界用例（当前环境无法创建符号链接）: %v", err)
	} else if _, err := s.resolveTaskWorkspaceFile("42", link); err == nil {
		t.Fatal("指向工作区外的符号链接应拒绝")
	}
	// 无任务上下文 / 非法 task id
	if _, err := s.resolveTaskWorkspaceFile("", insidePath(ws)); err == nil {
		t.Fatal("空 task id 应拒绝")
	}
	if _, err := s.resolveTaskWorkspaceFile("..", filepath.Join(ws, "ok.bin")); err == nil {
		t.Fatal("非法 task id 应拒绝")
	}
	if _, err := s.resolveTaskWorkspaceFile("42/../99", filepath.Join(ws, "ok.bin")); err == nil {
		t.Fatal("带路径分隔的 task id 应拒绝")
	}
}

func insidePath(ws string) string { return filepath.Join(ws, "ok.bin") }

func TestStageShareToolFenceAndTokenInURLOnly(t *testing.T) {
	s, dataDir := fenceServer(t)
	inside := filepath.Join(dataDir, "tasks", "42", "tool.bin")
	mustWrite(t, inside, "payload")
	outside := filepath.Join(dataDir, "secret.bin")
	mustWrite(t, outside, "secret")

	var logBuf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(prev) })

	var actSummary, actDetail string
	testStageActivity = func(summary, detail string) {
		actSummary, actDetail = summary, detail
	}
	t.Cleanup(func() { testStageActivity = nil })

	tool := s.stageShareTool()
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 42})
	res, err := tool.Call(ctx, mustJSON(map[string]any{"path": inside}), &actool.ToolContext{})
	if err != nil || res.IsError {
		t.Fatalf("工作区内文件应成功: err=%v res=%s", err, res.Flatten())
	}
	out := toolResultJSON(t, res)
	url, _ := out["url"].(string)
	if url == "" {
		t.Fatalf("工具结果应含下载 URL: %+v", out)
	}

	token := tokenFromURL(t, url)
	if !strings.Contains(url, token) {
		t.Fatal("工具结果 URL 必须含完整 token")
	}
	if actSummary == "" || actDetail == "" {
		t.Fatal("创建成功后应写入 Activity 文本")
	}
	if strings.Contains(actSummary, token) || strings.Contains(actDetail, token) {
		t.Fatalf("Activity 文本不得含完整 token\nsummary=%s\ndetail=%s", actSummary, actDetail)
	}
	if !strings.Contains(actSummary, token[:8]) || !strings.Contains(actDetail, token[:8]) {
		t.Fatalf("Activity 可以使用 token 前缀\nsummary=%s\ndetail=%s", actSummary, actDetail)
	}
	if strings.Contains(logBuf.String(), token) {
		t.Fatalf("log.Printf 不得写完整 token: %s", logBuf.String())
	}

	// 无任务上下文
	res, err = tool.Call(context.Background(), mustJSON(map[string]any{"path": inside}), &actool.ToolContext{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "缺少任务上下文") {
		t.Fatalf("无任务上下文应拒绝: %s", res.Flatten())
	}

	// 工作区外
	res, err = tool.Call(ctx, mustJSON(map[string]any{"path": outside}), &actool.ToolContext{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatalf("工作区外路径应拒绝: %s", res.Flatten())
	}
}

func TestStageCreateAPIPathRequiresTaskAndContentBase64Remains(t *testing.T) {
	s, dataDir := fenceServer(t)
	inside := filepath.Join(dataDir, "tasks", "7", "a.bin")
	mustWrite(t, inside, "abc")

	// 无 task_id 的 path 模式必须拒绝
	code, body := postStage(t, s, map[string]any{"path": inside})
	if code != 400 || !strings.Contains(body, "task_id") {
		t.Fatalf("无 task_id 的 path 模式应拒绝: %d %s", code, body)
	}

	// 有 task_id 且在工作区内应成功
	code, body = postStage(t, s, map[string]any{"path": inside, "task_id": "7"})
	if code != 200 {
		t.Fatalf("工作区内 path 应成功: %d %s", code, body)
	}
	var e stage.Entry
	if err := json.Unmarshal([]byte(body), &e); err != nil || e.Token == "" {
		t.Fatalf("应返回条目: %s", body)
	}

	// 工作区外 + 有 task_id 应拒绝
	outside := filepath.Join(dataDir, "nope.bin")
	mustWrite(t, outside, "x")
	code, body = postStage(t, s, map[string]any{"path": outside, "task_id": "7"})
	if code != 400 {
		t.Fatalf("工作区外 path 应拒绝: %d %s", code, body)
	}

	// content_base64 无 task_id 仍可创建（不读主机路径）
	code, body = postStage(t, s, map[string]any{
		"name":           "inline.bin",
		"content_base64": base64.StdEncoding.EncodeToString([]byte("inline")),
	})
	if code != 200 {
		t.Fatalf("content_base64 无 task_id 应保留: %d %s", code, body)
	}
}

func TestStageEventTextsOmitFullToken(t *testing.T) {
	token := "abcdefghijklmnopqrstuvwxyz012345" // 32 字符夹具，仅用于断言
	if len(token) != 32 {
		t.Fatal("夹具长度")
	}
	ev := stage.Event{
		Kind:  stage.EventPut,
		Entry: stage.Entry{Token: token, Name: "a.bin", Size: 3, ExpiresAt: time.Unix(0, 0).UTC()},
	}
	summary, detail := stageEventTexts(ev)
	if strings.Contains(summary, token) || strings.Contains(detail, token) {
		t.Fatalf("不得含完整 token: %s | %s", summary, detail)
	}
	if !strings.Contains(summary, token[:8]+"…") || !strings.Contains(detail, token[:8]+"…") {
		t.Fatalf("应含前缀: %s | %s", summary, detail)
	}
}

func postStage(t *testing.T, s *Server, body any) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/stage", bytes.NewReader(mustJSON(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.stageCreate(rec, req)
	return rec.Code, rec.Body.String()
}

func tokenFromURL(t *testing.T, rawURL string) string {
	t.Helper()
	// /s/<token>/<name>
	parts := strings.Split(strings.TrimPrefix(rawURL, "http://"), "/")
	for i, p := range parts {
		if p == "s" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	t.Fatalf("无法从 URL 解析 token: %s", rawURL)
	return ""
}
