// emp3r0r 驱动单测：mock emp3r0r cc operator API（CBOR-over-HTTP + ws msg_tunnel）。
// 只模拟协议族（operator 面 CBOR/ws），不经真实 emp3r0r；错误语义按诚实约定断言。
package session

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/gorilla/websocket"
)

// mockCC 是 in-process emp3r0r cc operator 面：HTTP+CBOR POST 端点 +
// ws msg_tunnel（send_command 触发后异步回流 JobID 帧）。
type mockCC struct {
	t *testing.T

	mu        sync.Mutex
	agents    []CCAgent
	commands  []string // 收到的命令
	forgotten []string
	jobDelay  time.Duration
	failHTTP  bool // 整体返回 500（模拟 cc 故障）

	upgrader websocket.Upgrader
	tunConns chan *websocket.Conn
}

func newMockCC(t *testing.T) (*mockCC, *CCClient) {
	m := &mockCC{t: t, tunConns: make(chan *websocket.Conn, 4)}
	srv := httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(srv.Close)
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", strings.TrimPrefix(srv.URL, "http://"))
	}
	cc := newTestCCClient(srv.URL, "test-operator", dial)
	t.Cleanup(func() { _ = cc.Close() })
	return m, cc
}

func (m *mockCC) handle(w http.ResponseWriter, r *http.Request) {
	if m.failHTTP {
		http.Error(w, "cc exploded", http.StatusInternalServerError)
		return
	}
	if r.Header.Get("operator_session") != "test-operator" {
		http.Error(w, "unknown operator", http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/operator/list_connected_agents":
		m.mu.Lock()
		list := append([]CCAgent(nil), m.agents...)
		m.mu.Unlock()
		b, _ := cbor.Marshal(list)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	case "/operator/send_command":
		body, _ := io.ReadAll(r.Body)
		var op ccOperation
		if err := cbor.Unmarshal(body, &op); err != nil {
			http.Error(w, "bad cbor", http.StatusBadRequest)
			return
		}
		if op.JobID == nil || op.Command == nil {
			http.Error(w, "missing job/command", http.StatusBadRequest)
			return
		}
		m.mu.Lock()
		m.commands = append(m.commands, *op.Command)
		m.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		// 异步经 msg_tunnel 回流结果（模拟真实 cc 延迟）。
		go func() {
			if m.jobDelay > 0 {
				time.Sleep(m.jobDelay)
			}
			select {
			case conn := <-m.tunConns:
				out := m.exec(*op.Command)
				msg := CCOperatorMsg{JobID: *op.JobID, Response: []byte(out)}
				b, _ := cbor.Marshal(msg)
				_ = conn.WriteMessage(websocket.BinaryMessage, b)
				// 连接可复用：放回供后续命令。
				select {
				case m.tunConns <- conn:
				default:
				}
			default:
			}
		}()
	case "/operator/forget_agent":
		body, _ := io.ReadAll(r.Body)
		var op ccOperation
		_ = cbor.Unmarshal(body, &op)
		m.mu.Lock()
		m.forgotten = append(m.forgotten, op.AgentTag)
		m.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	case "/operator/msg_tunnel":
		conn, err := m.upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		m.tunConns <- conn
		// 保持连接：读循环丢弃（测试不发 inbound）。
		for {
			if _, _, rerr := conn.ReadMessage(); rerr != nil {
				return
			}
		}
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// exec 在 mock 上模拟目标 shell：处理测试需要的少量命令形态。
func (m *mockCC) exec(cmd string) string {
	switch {
	case strings.HasPrefix(cmd, "echo "):
		return strings.TrimPrefix(cmd, "echo ") + "\n"
	case cmd == "command -v base64":
		return "/usr/bin/base64\n"
	case strings.HasPrefix(cmd, "wc -c < "):
		if size, ok := m.fileSize(cmd); ok {
			return fmt.Sprintf("%d\n", size)
		}
		return "" // 文件不存在：真实 wc 无 stdout
	case strings.HasPrefix(cmd, "dd if="):
		return m.fileChunk(cmd)
	case strings.Contains(cmd, "| base64 -d"):
		return m.fileWrite(cmd)
	default:
		return ""
	}
}

// 简单 in-memory 目标文件表（path → bytes），供 write/read 链路断言。
var mockFiles = struct {
	sync.Mutex
	files map[string][]byte
}{files: map[string][]byte{}}

func (m *mockCC) fileSize(cmd string) (int, bool) {
	p := strings.TrimPrefix(cmd, "wc -c < ")
	p = strings.TrimSuffix(p, " 2>/dev/null")
	p = strings.Trim(p, "'")
	mockFiles.Lock()
	defer mockFiles.Unlock()
	data, ok := mockFiles.files[p]
	return len(data), ok
}

func (m *mockCC) fileChunk(cmd string) string {
	// dd if='p' bs=N skip=S count=1
	var p string
	var bs, skip int64
	fmt.Sscanf(cmd, "dd if=%s bs=%d skip=%d", &p, &bs, &skip)
	p = strings.Trim(p, "'")
	mockFiles.Lock()
	defer mockFiles.Unlock()
	data := mockFiles.files[p]
	off := skip * bs
	if off >= int64(len(data)) {
		return ""
	}
	end := off + bs
	if end > int64(len(data)) {
		end = int64(len(data))
	}
	return string(data[off:end])
}

func (m *mockCC) fileWrite(cmd string) string {
	// printf '%s' '<b64>' | base64 -d (>|>>) 'path'
	// 按 ' 切分： [ "printf ", "%s", " ", "<b64>", " | base64 -d > ", "<path>" ]
	parts := strings.Split(cmd, "'")
	if len(parts) < 6 {
		return ""
	}
	b64, path := parts[3], parts[5]
	appendMode := strings.Contains(parts[4], ">>")
	raw, err := base64Decode(b64)
	if err != nil {
		return ""
	}
	mockFiles.Lock()
	defer mockFiles.Unlock()
	if appendMode {
		mockFiles.files[path] = append(mockFiles.files[path], raw...)
	} else {
		mockFiles.files[path] = raw
	}
	return ""
}

func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func TestEmp3r0rKindAndInterface(t *testing.T) {
	_, cc := newMockCC(t)
	e, err := NewEmp3r0r("tag-1", "10.0.0.5", cc)
	if err != nil {
		t.Fatalf("NewEmp3r0r: %v", err)
	}
	var _ Session = e
	if e.Kind() != "emp3r0r" {
		t.Fatalf("Kind=%q", e.Kind())
	}
	if e.AgentTag() != "tag-1" {
		t.Fatalf("AgentTag=%q", e.AgentTag())
	}
	sec := e.Secret()
	if sec.AgentTag != "tag-1" || !strings.HasPrefix(sec.URL, "emp3r0r://10.0.0.5") {
		t.Fatalf("Secret=%+v", sec)
	}
}

func TestEmp3r0rTestProbe(t *testing.T) {
	_, cc := newMockCC(t)
	e, _ := NewEmp3r0r("tag-1", "10.0.0.5", cc)
	if err := e.Test(context.Background()); err != nil {
		t.Fatalf("Test: %v", err)
	}
}

func TestEmp3r0rExec(t *testing.T) {
	m, cc := newMockCC(t)
	e, _ := NewEmp3r0r("tag-1", "10.0.0.5", cc)
	out, stderr, err := e.Exec(context.Background(), "echo hello", 10*time.Second)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if stderr != "" {
		t.Fatalf("stderr 非空: %q", stderr)
	}
	if !strings.Contains(out, "hello") {
		t.Fatalf("stdout=%q", out)
	}
	m.mu.Lock()
	if len(m.commands) == 0 {
		t.Fatal("未收到 send_command")
	}
	m.mu.Unlock()
}

func TestEmp3r0rWriteReadFile(t *testing.T) {
	mockFiles.Lock()
	mockFiles.files = map[string][]byte{}
	mockFiles.Unlock()

	_, cc := newMockCC(t)
	e, _ := NewEmp3r0r("tag-1", "10.0.0.5", cc)
	payload := []byte("ARTEX-emp3r0r-payload-\x00\x01\x02-binary-safe")
	path := "/tmp/artex_emp_test.bin"
	if err := e.WriteFile(context.Background(), path, payload); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	mockFiles.Lock()
	got := mockFiles.files[path]
	mockFiles.Unlock()
	if string(got) != string(payload) {
		t.Fatalf("写入内容不一致: got %d bytes", len(got))
	}
	back, err := e.ReadFile(context.Background(), path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(back) != string(payload) {
		t.Fatalf("读回不一致: %d vs %d bytes", len(back), len(payload))
	}
}

func TestEmp3r0rReadFileMissing(t *testing.T) {
	mockFiles.Lock()
	mockFiles.files = map[string][]byte{}
	mockFiles.Unlock()

	_, cc := newMockCC(t)
	e, _ := NewEmp3r0r("tag-1", "10.0.0.5", cc)
	_, err := e.ReadFile(context.Background(), "/nonexistent.bin")
	if err == nil {
		t.Fatal("期望错误")
	}
	if !strings.Contains(err.Error(), "不可读") {
		t.Fatalf("错误应诚实说明不可读: %v", err)
	}
}

func TestEmp3r0rExecCCDown(t *testing.T) {
	m, cc := newMockCC(t)
	m.failHTTP = true
	e, _ := NewEmp3r0r("tag-1", "10.0.0.5", cc)
	_, _, err := e.Exec(context.Background(), "echo x", 10*time.Second)
	if err == nil {
		t.Fatal("期望错误")
	}
	if !strings.Contains(err.Error(), "msg_tunnel") && !strings.Contains(err.Error(), "500") {
		t.Fatalf("错误应带 cc 失败原因: %v", err)
	}
}

func TestEmp3r0rAgentsAndForget(t *testing.T) {
	m, cc := newMockCC(t)
	m.mu.Lock()
	m.agents = []CCAgent{{Tag: "abc123", Hostname: "web01", IPs: []string{"10.0.0.5"}, OS: "Linux", User: "www"}}
	m.mu.Unlock()
	agents, err := cc.Agents(context.Background())
	if err != nil {
		t.Fatalf("Agents: %v", err)
	}
	if len(agents) != 1 || agents[0].Tag != "abc123" {
		t.Fatalf("agents=%+v", agents)
	}
	if err := cc.ForgetAgent(context.Background(), "abc123"); err != nil {
		t.Fatalf("ForgetAgent: %v", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.forgotten) != 1 || m.forgotten[0] != "abc123" {
		t.Fatalf("forgotten=%v", m.forgotten)
	}
}

func TestEmp3r0rRestore(t *testing.T) {
	_, cc := newMockCC(t)
	sec := Secret{URL: "emp3r0r://10.0.0.5", AgentTag: "tag-9"}
	e, err := RestoreEmp3r0r(42, sec, cc)
	if err != nil {
		t.Fatalf("RestoreEmp3r0r: %v", err)
	}
	if e.ID() != 42 || e.AgentTag() != "tag-9" || e.Host() != "10.0.0.5" {
		t.Fatalf("恢复结果 ID=%d tag=%s host=%s", e.ID(), e.AgentTag(), e.Host())
	}
}

func TestEmp3r0rNewRequiresTagAndClient(t *testing.T) {
	if _, err := NewEmp3r0r("", "h", nil); err == nil {
		t.Fatal("空 tag 应报错")
	}
	if _, err := NewEmp3r0r("t", "h", nil); err == nil {
		t.Fatal("nil client 应报错")
	}
}
