// emp3r0r 驱动单测：mock emp3r0r cc operator API（CBOR-over-HTTP + ws msg_tunnel）。
// 只模拟协议族（operator 面 CBOR/ws），不经真实 emp3r0r；错误语义按诚实约定断言。
package session

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	failWrite bool // fileWrite 静默失败（模拟远端写入失败：哨兵缺失、文件未变）

	upgrader websocket.Upgrader
	tunConns chan *websocket.Conn
	tunWrite sync.Mutex // 串行化 ws 写入（gorilla 不允许并发写）
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
				m.tunWrite.Lock()
				_ = conn.WriteMessage(websocket.BinaryMessage, b)
				m.tunWrite.Unlock()
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
		m.mu.Lock()
		fail := m.failWrite
		m.mu.Unlock()
		out, ok := "", false
		if !fail {
			out, ok = m.fileWrite(cmd)
		}
		// `&& echo <sent>` 尾哨兵：写入成功才回显；解码失败 = 远端命令失败。
		if i := strings.LastIndex(cmd, "&& echo "); i >= 0 && ok {
			return out + strings.TrimSpace(cmd[i+8:]) + "\n"
		}
		return out
	case strings.HasPrefix(cmd, "sha256sum") || strings.HasPrefix(cmd, "md5sum"):
		return m.fileHash(cmd)
	case strings.Contains(cmd, "kill_tunnel"):
		m.killTunnel()
		return ""
	default:
		return ""
	}
}

// killTunnel 关闭当前 msg_tunnel 服务端连接（模拟断线）。
func (m *mockCC) killTunnel() {
	for {
		select {
		case conn := <-m.tunConns:
			_ = conn.Close()
		default:
			return
		}
	}
}

func (m *mockCC) fileHash(cmd string) string {
	// sha256sum 'p' || md5sum 'p'
	algo := "sha256"
	p := strings.TrimPrefix(cmd, "sha256sum ")
	if strings.HasPrefix(cmd, "md5sum") {
		algo = "md5"
		p = strings.TrimPrefix(cmd, "md5sum ")
	}
	if i := strings.Index(p, "||"); i >= 0 {
		p = strings.TrimSpace(p[:i])
	}
	if i := strings.Index(p, "2>/"); i >= 0 {
		p = strings.TrimSpace(p[:i])
	}
	p = strings.Trim(p, "'")
	mockFiles.Lock()
	defer mockFiles.Unlock()
	data, ok := mockFiles.files[p]
	if !ok {
		return ""
	}
	if algo == "md5" {
		sum := md5.Sum(data)
		return fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), p)
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), p)
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

func (m *mockCC) fileWrite(cmd string) (string, bool) {
	// printf '%s' '<b64>' | base64 -d (>|>>) 'path'
	// 按 ' 切分： [ "printf ", "%s", " ", "<b64>", " | base64 -d > ", "<path>" ]
	parts := strings.Split(cmd, "'")
	if len(parts) < 6 {
		return "", false
	}
	b64, path := parts[3], parts[5]
	appendMode := strings.Contains(parts[4], ">>")
	raw, err := base64Decode(b64)
	if err != nil {
		return "", false
	}
	mockFiles.Lock()
	defer mockFiles.Unlock()
	if appendMode {
		mockFiles.files[path] = append(mockFiles.files[path], raw...)
	} else {
		mockFiles.files[path] = raw
	}
	return "", true
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

// waitTunnelDead 等读循环把当前连接判死（tunAlive=false）。
func waitTunnelDead(t *testing.T, cc *CCClient) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		cc.tunMu.Lock()
		dead := !cc.tunAlive
		cc.tunMu.Unlock()
		if dead {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("断线未被读循环判死")
}

// TestEmp3r0rTunnelReconnect 断线后重连：旧连接滞留 job 判死，新命令走新连接。
func TestEmp3r0rTunnelReconnect(t *testing.T) {
	m, cc := newMockCC(t)
	e, _ := NewEmp3r0r("tag-1", "10.0.0.5", cc)
	if _, _, err := e.Exec(context.Background(), "echo first", 10*time.Second); err != nil {
		t.Fatalf("首次 Exec: %v", err)
	}
	m.killTunnel()
	waitTunnelDead(t, cc)
	// 断线后新命令经重连通道照常回结果。
	out, _, err := e.Exec(context.Background(), "echo second", 10*time.Second)
	if err != nil {
		t.Fatalf("重连后 Exec: %v", err)
	}
	if !strings.Contains(out, "second") {
		t.Fatalf("out=%q", out)
	}
}

// TestEmp3r0rTunnelDeadJobKilled 断线时滞留 job 收到断线语义而非无限等。
func TestEmp3r0rTunnelDeadJobKilled(t *testing.T) {
	m, cc := newMockCC(t)
	m.jobDelay = 3 * time.Second // 结果慢于断线
	e, _ := NewEmp3r0r("tag-1", "10.0.0.5", cc)
	done := make(chan error, 1)
	go func() {
		_, _, err := e.Exec(context.Background(), "echo slow", 30*time.Second)
		done <- err
	}()
	// 等 send_command 发出后断线。
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		n := len(m.commands)
		m.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	m.killTunnel()
	waitTunnelDead(t, cc)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("滞留 job 应上报断线错误")
		}
		if !strings.Contains(err.Error(), "msg_tunnel") && !strings.Contains(err.Error(), "断线") {
			t.Fatalf("错误应说明回流通道断线: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("滞留 job 未被及时判死")
	}
}

// TestEmp3r0rOldLoopDoesNotKillNewJobs 旧读循环退出不得清掉新连接的 job：
// conn1 死 → conn2 重连 → 新命令在其上挂 job → conn1 的清理不得误杀。
func TestEmp3r0rOldLoopDoesNotKillNewJobs(t *testing.T) {
	m, cc := newMockCC(t)
	e, _ := NewEmp3r0r("tag-1", "10.0.0.5", cc)
	if _, _, err := e.Exec(context.Background(), "echo warm", 10*time.Second); err != nil {
		t.Fatalf("warm Exec: %v", err)
	}
	m.killTunnel()
	waitTunnelDead(t, cc)
	out, _, err := e.Exec(context.Background(), "echo fresh", 10*time.Second)
	if err != nil {
		t.Fatalf("重连 Exec: %v", err)
	}
	if !strings.Contains(out, "fresh") {
		t.Fatalf("out=%q", out)
	}
}

// TestEmp3r0rConcurrentSend 并发 SendCommand/ensureTunnel 竞态（-race 下验证）。
func TestEmp3r0rConcurrentSend(t *testing.T) {
	_, cc := newMockCC(t)
	e, _ := NewEmp3r0r("tag-1", "10.0.0.5", cc)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, err := e.Exec(context.Background(),
				fmt.Sprintf("echo c%d", i), 15*time.Second)
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("并发 Exec: %v", err)
		}
	}
}

// TestEmp3r0rWgDialConcurrent 并发首次拨号竞态：wgOnce 一次性拉起，
// 坏配置下并发调用都拿到同一错误且不改写共享拨号器（-race）。
func TestEmp3r0rWgDialConcurrent(t *testing.T) {
	cc, err := NewCCClient(Emp3r0rConfig{Endpoint: "127.0.0.1:1", ServerIP: "172.16.254.1"})
	if err != nil {
		t.Fatalf("NewCCClient: %v", err)
	}
	defer cc.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, derr := cc.dial(context.Background(), "tcp", "172.16.254.1:13378")
			errs <- derr
		}()
	}
	wg.Wait()
	close(errs)
	var first error
	for err := range errs {
		if err == nil {
			t.Fatal("缺 WG 凭据应报错")
		}
		if first == nil {
			first = err
		} else if err.Error() != first.Error() {
			t.Fatalf("并发拨号错误不一致: %v vs %v", first, err)
		}
	}
}

// TestEmp3r0rWriteFileChunkVerified 分块写入每块哨兵确认 + sha256 内容校验。
func TestEmp3r0rWriteFileChunkVerified(t *testing.T) {
	mockFiles.Lock()
	mockFiles.files = map[string][]byte{}
	mockFiles.Unlock()

	m, cc := newMockCC(t)
	e, _ := NewEmp3r0r("tag-1", "10.0.0.5", cc)
	payload := make([]byte, empWriteChunk+7) // 跨块
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	path := "/tmp/artex_emp_chunk.bin"
	if err := e.WriteFile(context.Background(), path, payload); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	m.mu.Lock()
	cmds := append([]string(nil), m.commands...)
	m.mu.Unlock()
	sents := 0
	for _, c := range cmds {
		if strings.Contains(c, "&& echo ARTEX_W_") {
			sents++
		}
	}
	if sents != 2 {
		t.Fatalf("应为每块一条哨兵命令（2 块），实 %d", sents)
	}
	mockFiles.Lock()
	got := mockFiles.files[path]
	mockFiles.Unlock()
	if len(got) != len(payload) || string(got) != string(payload) {
		t.Fatalf("写入内容不一致: %d vs %d", len(got), len(payload))
	}
}

// TestEmp3r0rWriteFileFailedChunk 远端命令失败（哨兵缺失）必须报错而非只看大小。
func TestEmp3r0rWriteFileFailedChunk(t *testing.T) {
	mockFiles.Lock()
	// 预置等长旧文件：若只校验大小会误判成功。
	old := []byte("ARTEX-emp3r0r-payload-\x00\x01\x02-binary-safe")
	mockFiles.files = map[string][]byte{"/tmp/artex_emp_stale.bin": old}
	mockFiles.Unlock()

	m, cc := newMockCC(t)
	// 破坏写入：让 fileWrite 路径静默失败（注入非法 b64 不可行——直接拦截 mock）。
	m.mu.Lock()
	m.failWrite = true
	m.mu.Unlock()
	e, _ := NewEmp3r0r("tag-1", "10.0.0.5", cc)
	err := e.WriteFile(context.Background(), "/tmp/artex_emp_stale.bin", []byte("new-content-same-length-0123456789ab"))
	if err == nil {
		t.Fatal("远端写入失败必须报错（等长旧文件不得判成功）")
	}
}
