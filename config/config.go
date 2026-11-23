// Package config loads runtime configuration from a JSON file, with environment
// variables taking precedence. Currently it carries the PostgreSQL connection.
package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Database is the PostgreSQL connection config. Either set DSN directly, or set
// the component fields and a DSN is assembled from them.
type Database struct {
	DSN      string `json:"dsn"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	DBName   string `json:"dbname"`
	SSLMode  string `json:"sslmode"`
}

// Config is the on-disk config file shape.
type Config struct {
	Database           Database `json:"database"`
	SkillDir           string   `json:"skill_dir"`
	CallbackAddr       string   `json:"callback_addr"`
	TunnelPortRange    string   `json:"tunnel_port_range"`
	TaskProxyPortRange string   `json:"task_proxy_port_range"`
	OwnInfraHosts      []string `json:"own_infra_hosts"`
	// GateMode 是伪装门控（off / detect / enforce）。空字符串表示本文件未配置，
	// 由 ResolveGate 继续看更低优先级。优先级与未知值回落见 gate.go。
	GateMode string `json:"gate_mode"`
	// JWT 签名寿命与轮换。环境变量优先；见 JWTTTL / JWTRotationPeriod / JWTGrace。
	// 这些字段不轮换 jwt.key（AES 主密钥）。
	JWTTTL            string `json:"jwt_ttl"`
	JWTRotationPeriod string `json:"jwt_rotation_period"`
	JWTGrace          string `json:"jwt_grace"`
	// emp3r0r cc sidecar 集成（reverse implant 会话）。
	Emp3r0r Emp3r0r `json:"emp3r0r"`
}

// Emp3r0r 是 emp3r0r cc sidecar 连接配置。emp3r0r v5 的 operator API 是
// HTTP+CBOR、绑定在 userspace WireGuard netstack 上，本平台以 provisioning 的
// operator WG 凭据接入 cc 的 WG overlay。凭据来自 cc 端 wg_config.json。
type Emp3r0r struct {
	Enabled           bool   `json:"enabled"`
	WGEndpoint        string `json:"wg_endpoint"`           // cc WG UDP 端点 host:port（cc --operator-port）
	WGServerPublicKey string `json:"wg_server_public_key"`  // cc WG server 公钥
	WGServerIP        string `json:"wg_server_ip"`          // cc WG server IP（operator HTTP 在此监听）
	WGOperatorIP      string `json:"wg_operator_ip"`        // 本平台 operator WG IP
	WGOperatorKey     string `json:"wg_operator_key"`       // 本平台 operator WG 私钥
	OperatorPort      int    `json:"operator_port"`         // operator HTTP 端口；0 = wg_endpoint 端口+1
	OperatorSession   string `json:"operator_session"`      // operator_session 头值；空 = wg_operator_ip
	AgentBinary       string `json:"agent_binary"`          // deploy_emp3r0r 投递的 agent 二进制路径
	PollIntervalSec   int    `json:"poll_interval_seconds"` // agent 上线轮询间隔；0=15
	AgentWaitSec      int    `json:"agent_wait_seconds"`    // deploy 等回连上限；0=120
	// WGConfigPath 是 cc 端 wg_config.json 的挂载路径（compose 挂
	// /emp3r0r-workspace）。wg_* 凭据缺省时从中自动 provisioning：
	// server_ip / server_private_key（推导公钥）与 operators.<OperatorName>。
	WGConfigPath string `json:"wg_config_path"` // 默认 /emp3r0r-workspace/wg_config.json
	OperatorName string `json:"operator_name"`  // wg_config.json 中本平台 operator 名；默认 artex，空=第一条
}

// BaseDir is the directory that anchors all runtime artifacts (config.json and
// the data/ store). It is the directory the running binary lives in, so a
// distributed executable keeps its files next to itself on any OS (Windows,
// Linux, …) regardless of the working directory it is launched from.
//
// When launched via `go run`, the binary is throwaway: it sits either in a temp
// build dir (cache miss → fresh link) OR straight inside the Go build cache
// (cache hit → run from $GOCACHE/.../...-d). We detect both and fall back to the
// current working directory so dev artifacts (data/, transcripts) and config
// resolve against the project dir, not the throwaway binary's location.
func BaseDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	dir := filepath.Dir(exe)
	if isGoRunDir(dir) {
		return "." // throwaway `go run` binary → use CWD
	}
	return dir
}

// isGoRunDir reports whether dir is where `go run` parked its executable: under
// the system temp dir (cache miss), or anywhere inside a Go build cache
// (…/go-build/…, the cache-hit case — NOT under os.TempDir(), which is why the
// old temp-only check failed intermittently). In both cases the binary is
// throwaway, so config/data must resolve against the CWD.
func isGoRunDir(dir string) bool {
	if tmp := os.TempDir(); tmp != "" {
		if rel, err := filepath.Rel(tmp, dir); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	for _, seg := range strings.Split(filepath.ToSlash(dir), "/") {
		if seg == "go-build" {
			return true
		}
	}
	return false
}

// Path returns the config file path. Resolution order:
//  1. env ARTEX_CONFIG (explicit override)
//  2. ./config.json in the current working directory (running from the project
//     dir — robust no matter where `go run` placed the temp/cached binary)
//  3. config.json next to the executable (a distributed binary keeps it beside)
//
// The first existing file wins. If none exist, the CWD path is returned so the
// "not found" message points at the project dir the user most likely expected.
func Path() string {
	if v := strings.TrimSpace(os.Getenv("ARTEX_CONFIG")); v != "" {
		return v
	}
	var candidates []string
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, "config.json"))
	}
	candidates = append(candidates, filepath.Join(BaseDir(), "config.json"))
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return candidates[0]
}

// Load reads and parses the config file. A missing/unreadable file yields a zero
// Config (so callers fall back to defaults) rather than an error.
func Load() Config {
	var c Config
	b, err := os.ReadFile(Path())
	if err != nil {
		return c
	}
	_ = json.Unmarshal(b, &c)
	return c
}

// SkillDir returns the skill root directory with precedence:
//
//	env ARTEX_SKILL_DIR  >  config file (skill_dir)  >  BaseDir()/skills
//
// The directory is created if it does not exist.
func SkillDir() string {
	var d string
	if v := strings.TrimSpace(os.Getenv("ARTEX_SKILL_DIR")); v != "" {
		d = v
	} else if v := strings.TrimSpace(Load().SkillDir); v != "" {
		d = v
	} else {
		d = filepath.Join(BaseDir(), "skills")
	}
	_ = os.MkdirAll(d, 0o755)
	return d
}

// PostgresDSN resolves the connection string with precedence:
//
//	env ARTEX_PG_DSN  >  config file (database.dsn, or assembled from fields)
//
// There is NO built-in fallback: when neither source supplies a database config,
// it returns an error naming the config path it inspected, so startup fails loudly
// instead of silently connecting to a wrong default. source describes where the
// DSN came from (for startup logging).
func PostgresDSN() (dsn, source string, err error) {
	if v := strings.TrimSpace(os.Getenv("ARTEX_PG_DSN")); v != "" {
		return v, "环境变量 ARTEX_PG_DSN", nil
	}
	db := Load().Database
	if d := strings.TrimSpace(db.DSN); d != "" {
		return d, "配置文件 " + Path() + " (database.dsn)", nil
	}
	if db.Host != "" || db.DBName != "" || db.User != "" {
		return db.buildDSN(), "配置文件 " + Path() + " (database 字段)", nil
	}
	return "", "", fmt.Errorf("未找到数据库配置：环境变量 ARTEX_PG_DSN 未设置，且配置文件 %s 未提供 database（dsn 或 host/user/dbname）。请创建该配置文件或设置环境变量后重试", Path())
}

func (d Database) buildDSN() string {
	host := d.Host
	if host == "" {
		host = "127.0.0.1"
	}
	port := d.Port
	if port == 0 {
		port = 5432
	}
	ssl := d.SSLMode
	if ssl == "" {
		ssl = "disable"
	}
	u := url.URL{
		Scheme: "postgres",
		Host:   host + ":" + strconv.Itoa(port),
		Path:   "/" + d.DBName,
	}
	if d.User != "" {
		if d.Password != "" {
			u.User = url.UserPassword(d.User, d.Password)
		} else {
			u.User = url.User(d.User)
		}
	}
	u.RawQuery = url.Values{"sslmode": {ssl}}.Encode()
	return u.String()
}

// keywordSecret 匹配 libpq 风格键值串里的口令键（长短优先），值可加引号。
var keywordSecret = regexp.MustCompile(`(?i)(^|[\s])((?:password|passwd|pwd|pass)=)('[^']*'|"[^"]*"|[^\s]+)`)

func redactKeywordSecrets(s string) string {
	return keywordSecret.ReplaceAllString(s, "${1}${2}****")
}

// Redact 返回供日志使用的脱敏 DSN。URL 形态（postgres://user:pass@host/db）
// 仍按原逻辑打码 User 中的口令；url.Parse 失败或没有 User 时，再处理
// key=value（password/passwd/pwd/pass）里的口令。
func Redact(dsn string) string {
	u, err := url.Parse(dsn)
	// 无 scheme 的 key=value 串会被 url.Parse 收成 Path 并把空格编成 %20，
	// 必须走原文打码，不能先 String()。
	if err != nil || u.Scheme == "" {
		return redactKeywordSecrets(dsn)
	}
	if u.User != nil {
		if _, hasPw := u.User.Password(); hasPw {
			u.User = url.UserPassword(u.User.Username(), "****")
		}
	}
	return redactKeywordSecrets(u.String())
}

// CallbackAddr resolves the platform callback address:
//
//	env ARTEX_CALLBACK_ADDR  >  config file (callback_addr)
//
// 隧道回连平台时使用；未设置时部署工具应明确报错，不阻断平台启动。
func CallbackAddr() string {
	if v := strings.TrimSpace(os.Getenv("ARTEX_CALLBACK_ADDR")); v != "" {
		return v
	}
	return strings.TrimSpace(Load().CallbackAddr)
}

// TunnelPortRange resolves the tunnel port pool ("min-max"):
//
//	env ARTEX_TUNNEL_PORT_RANGE  >  config file  >  "20000-21000"
func TunnelPortRange() string {
	if v := strings.TrimSpace(os.Getenv("ARTEX_TUNNEL_PORT_RANGE")); v != "" {
		return v
	}
	if v := strings.TrimSpace(Load().TunnelPortRange); v != "" {
		return v
	}
	return "20000-21000"
}

// HostPaceDefaultRPS is the built-in polite per-host request rate used on first
// run when no host_pace_rps setting has been chosen yet. 0 would disable pacing.
const HostPaceDefaultRPS = 10.0

// HostPaceRPS resolves the startup default for per-host pacing: ARTEX_HOST_PACE_RPS
// if set (>=0; 0 disables), else HostPaceDefaultRPS. A persisted host_pace_rps
// setting, once chosen, overrides this.
func HostPaceRPS() float64 {
	if v := strings.TrimSpace(os.Getenv("ARTEX_HOST_PACE_RPS")); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 {
			return f
		}
	}
	return HostPaceDefaultRPS
}

// Emp3r0rConfig 解析 emp3r0r sidecar 配置。优先级：ARTEX_EMP3R0R_* 环境变量 >
// 配置文件 emp3r0r 段。Enabled 除文件 enabled 外也可用 ARTEX_EMP3R0R=on/off。
func Emp3r0rConfig() Emp3r0r {
	c := Load().Emp3r0r
	if v := strings.TrimSpace(os.Getenv("ARTEX_EMP3R0R_ENDPOINT")); v != "" {
		c.WGEndpoint = v
	}
	if v := strings.TrimSpace(os.Getenv("ARTEX_EMP3R0R_SERVER_KEY")); v != "" {
		c.WGServerPublicKey = v
	}
	if v := strings.TrimSpace(os.Getenv("ARTEX_EMP3R0R_SERVER_IP")); v != "" {
		c.WGServerIP = v
	}
	if v := strings.TrimSpace(os.Getenv("ARTEX_EMP3R0R_OPERATOR_IP")); v != "" {
		c.WGOperatorIP = v
	}
	if v := strings.TrimSpace(os.Getenv("ARTEX_EMP3R0R_OPERATOR_KEY")); v != "" {
		c.WGOperatorKey = v
	}
	if v := strings.TrimSpace(os.Getenv("ARTEX_EMP3R0R_OPERATOR_PORT")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.OperatorPort = n
		}
	}
	if v := strings.TrimSpace(os.Getenv("ARTEX_EMP3R0R_SESSION")); v != "" {
		c.OperatorSession = v
	}
	if v := strings.TrimSpace(os.Getenv("ARTEX_EMP3R0R_AGENT_BINARY")); v != "" {
		c.AgentBinary = v
	}
	if v := strings.TrimSpace(os.Getenv("ARTEX_EMP3R0R_POLL_INTERVAL")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.PollIntervalSec = n
		}
	}
	if v := strings.TrimSpace(os.Getenv("ARTEX_EMP3R0R_WAIT_SECONDS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.AgentWaitSec = n
		}
	}
	if v := strings.TrimSpace(os.Getenv("ARTEX_EMP3R0R_WG_CONFIG")); v != "" {
		c.WGConfigPath = v
	}
	if v := strings.TrimSpace(os.Getenv("ARTEX_EMP3R0R_OPERATOR_NAME")); v != "" {
		c.OperatorName = v
	}
	if v := strings.TrimSpace(os.Getenv("ARTEX_EMP3R0R")); v != "" {
		switch strings.ToLower(v) {
		case "on", "1", "true", "enabled":
			c.Enabled = true
		case "off", "0", "false", "disabled":
			c.Enabled = false
		}
	}
	// wg_config.json provisioning 兜底：wg_* 缺项时从 cc 挂载文件补齐
	// （显式 env / 配置文件优先，文件只填空位）。
	c.fillFromWgConfig()
	return c
}

// empWgConfigFile 对应 cc 端 wg_config.json（emp3r0r SavedWgConfig）。
type empWgConfigFile struct {
	ServerIP         string `json:"server_ip"`
	ServerPrivateKey string `json:"server_private_key"`
	Operators        []struct {
		Name       string `json:"name"`
		IP         string `json:"ip"`
		PrivateKey string `json:"private_key"`
		PublicKey  string `json:"public_key"`
	} `json:"operators"`
}

// fillFromWgConfig 从 cc provisioning 的 wg_config.json 补齐缺失的 wg_* 字段。
// server_private_key 推导 server 公钥；operator 按 OperatorName 匹配
// （空 = 第一条）。文件缺失/损坏静默跳过——配置不全由启动检查诚实报错。
func (c *Emp3r0r) fillFromWgConfig() {
	path := strings.TrimSpace(c.WGConfigPath)
	if path == "" {
		path = "/emp3r0r-workspace/wg_config.json"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var wc empWgConfigFile
	if err := json.Unmarshal(data, &wc); err != nil {
		return
	}
	if c.WGServerIP == "" {
		c.WGServerIP = strings.TrimSpace(wc.ServerIP)
	}
	if c.WGServerPublicKey == "" && strings.TrimSpace(wc.ServerPrivateKey) != "" {
		if priv, kerr := wgtypes.ParseKey(strings.TrimSpace(wc.ServerPrivateKey)); kerr == nil {
			c.WGServerPublicKey = priv.PublicKey().String()
		}
	}
	if c.WGOperatorIP == "" || c.WGOperatorKey == "" {
		name := strings.TrimSpace(c.OperatorName)
		for i, op := range wc.Operators {
			if name != "" && op.Name != name {
				continue
			}
			if name == "" && i != 0 {
				continue
			}
			if c.WGOperatorIP == "" {
				c.WGOperatorIP = strings.TrimSpace(op.IP)
			}
			if c.WGOperatorKey == "" {
				c.WGOperatorKey = strings.TrimSpace(op.PrivateKey)
			}
			break
		}
	}
}

// Emp3r0rPollInterval 是 agent 上线轮询间隔（默认 15s）。
func (e Emp3r0r) PollInterval() time.Duration {
	if e.PollIntervalSec > 0 {
		return time.Duration(e.PollIntervalSec) * time.Second
	}
	return 15 * time.Second
}

// Emp3r0rAgentWait 是 deploy_emp3r0r 等回连上限（默认 120s）。
func (e Emp3r0r) AgentWait() time.Duration {
	if e.AgentWaitSec > 0 {
		return time.Duration(e.AgentWaitSec) * time.Second
	}
	return 120 * time.Second
}

// TaskProxyEnabled reports whether per-task MITM instances are on.
// Default on; env ARTEX_TASK_PROXY=off/0/false disables (worker then keeps
// using the single global recording proxy).
func TaskProxyEnabled() bool {
	v := strings.TrimSpace(os.Getenv("ARTEX_TASK_PROXY"))
	return !(strings.EqualFold(v, "off") || v == "0" || strings.EqualFold(v, "false"))
}

// TaskProxyPortRange resolves the per-task MITM port pool ("min-max"):
//
//	env ARTEX_TASK_PROXY_PORT_RANGE  >  config file  >  "21100-21199"
func TaskProxyPortRange() string {
	if v := strings.TrimSpace(os.Getenv("ARTEX_TASK_PROXY_PORT_RANGE")); v != "" {
		return v
	}
	if v := strings.TrimSpace(Load().TaskProxyPortRange); v != "" {
		return v
	}
	return "21100-21199"
}

// Summary 返回可安全落库/上报的「有效配置」摘要。任务溯源需要知道当时跑的是哪套
// 配置，但配置里混着凭据（DSN、库口令、JWT 相关、emp3r0r 密钥），所以这里按白名单
// 取值：只收行为相关的开关与范围，凭据一律只记「是否配置」这一个布尔，绝不记原文。
// 新增配置字段默认不进摘要——必须显式加进来，避免哪天把新的密钥顺手带出去。
func (c Config) Summary() map[string]any {
	return map[string]any{
		"skill_dir":             c.SkillDir,
		"callback_addr":         c.CallbackAddr,
		"tunnel_port_range":     c.TunnelPortRange,
		"task_proxy_port_range": c.TaskProxyPortRange,
		"own_infra_hosts":       len(c.OwnInfraHosts),
		"gate_mode":             c.GateMode,
		"jwt_ttl":               c.JWTTTL,
		"jwt_rotation_period":   c.JWTRotationPeriod,
		"jwt_grace":             c.JWTGrace,
		"db_host":               c.Database.Host,
		"db_port":               c.Database.Port,
		"db_name":               c.Database.DBName,
		"db_sslmode":            c.Database.SSLMode,
		"db_password_set":       c.Database.Password != "",
		"db_dsn_set":            c.Database.DSN != "",
		"emp3r0r_enabled":       c.Emp3r0r.Enabled,
	}
}
