package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// 本文件实现自定义工具执行器(docs/自定义工具设计.md)。system=false 的 tools 行按
// kind 分派:command(渲染命令→复用 Bash 底层 run)、script(仅 Python;写临时文件、
// stdin=参数 JSON + env TOOL_*、用配置的解释器)、http(原生请求+可设代理)。这些工具
// 像流量/编排工具一样 seed 不需要(它们本就在 tools 表),经 hostTools 注入、按绑定过滤。

// ---------- 自定义工具 CRUD ----------

type customToolReq struct {
	Key         string          `json:"key"`
	Description string          `json:"description"`
	Schema      json.RawMessage `json:"schema"`
	Agents      []string        `json:"agents"`
	Enabled     bool            `json:"enabled"`
	Kind        string          `json:"kind"` // command | script | http
	Exec        json.RawMessage `json:"exec"`
	Deferred    bool            `json:"deferred"`
}

var reToolKey = reAgentKey // 同 agent key 规则:小写字母开头 + 小写字母/数字/下划线

func (s *Server) pgCreateCustomTool(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req customToolReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	req.Key = strings.TrimSpace(req.Key)
	if !reToolKey.MatchString(req.Key) {
		writeErr(w, 400, "key 需小写字母开头，仅含小写字母/数字/下划线")
		return
	}
	if req.Kind != "command" && req.Kind != "script" && req.Kind != "http" && req.Kind != "shell" {
		writeErr(w, 400, "kind 需为 command / script / http / shell")
		return
	}
	if req.Kind == "http" && !hasSchemaProps(req.Schema) {
		writeErr(w, 400, "http 工具必须提供参数 JSON Schema(不能留空)")
		return
	}
	if exist, _ := pg.GetTool(req.Key); exist != nil {
		writeErr(w, 409, "该 key 已存在(内置或自定义工具)")
		return
	}
	if err := pg.CreateCustomTool(&db.Tool{
		Key: req.Key, Description: req.Description, Schema: req.Schema, Agents: req.Agents,
		Enabled: req.Enabled, Kind: req.Kind, Exec: req.Exec, Deferred: req.Deferred,
	}); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"key": req.Key})
}

func (s *Server) pgUpdateCustomTool(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	key := r.PathValue("key")
	existing, err := pg.GetTool(key)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if existing == nil || existing.System {
		writeErr(w, 400, "只能编辑自定义工具")
		return
	}
	var req customToolReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Kind != "command" && req.Kind != "script" && req.Kind != "http" && req.Kind != "shell" {
		writeErr(w, 400, "kind 需为 command / script / http / shell")
		return
	}
	if req.Kind == "http" && !hasSchemaProps(req.Schema) {
		writeErr(w, 400, "http 工具必须提供参数 JSON Schema(不能留空)")
		return
	}
	if err := pg.UpdateCustomTool(&db.Tool{
		Key: key, Description: req.Description, Schema: req.Schema, Agents: req.Agents,
		Enabled: req.Enabled, Kind: req.Kind, Exec: req.Exec, Deferred: req.Deferred,
	}); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) pgDeleteCustomTool(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	key := r.PathValue("key")
	if err := pg.DeleteCustomTool(key); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": key})
}

// testToolReq is a dry-run request from the editor: run the given (possibly unsaved)
// exec spec with sample params, without persisting the tool. Same executor path as a
// real tool call — it runs arbitrary command/script/http on the server, which the
// custom-tool feature already allows, so no new capability is granted.
type testToolReq struct {
	Kind   string          `json:"kind"` // command | script | http
	Exec   json.RawMessage `json:"exec"`
	Params map[string]any  `json:"params"`
}

// pgTestCustomTool executes an exec spec once and returns its raw output + error
// flag, so the editor can debug a tool before saving it. Per-kind timeouts still
// apply from the exec spec (with defaults); the outer ceiling is a hard backstop.
func (s *Server) pgTestCustomTool(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req testToolReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "无效的请求体")
		return
	}
	params := req.Params
	if params == nil {
		params = map[string]any{}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	tc := &actool.ToolContext{WorkingDir: s.m.dir} // run in the project dir, like a real call
	var res actool.Result
	switch req.Kind {
	case "command":
		res, _ = s.runCommandTool(ctx, req.Exec, params, tc)
	case "script":
		res, _ = s.runScriptTool(ctx, "test", req.Exec, params, tc)
	case "http":
		res, _ = s.runHTTPTool(ctx, req.Exec, params, tc)
	case "shell":
		writeErr(w, 400, "shell 类型工具是 bash 环境声明，无可执行内容")
		return
	default:
		writeErr(w, 400, "未知工具类型: "+req.Kind)
		return
	}
	writeJSON(w, 200, map[string]any{"output": res.Flatten(), "is_error": res.IsError})
}

// ---------- Python 解释器(检测 + 入库 + 覆盖) ----------

const settingPythonInterp = "python_interpreter"

// detectPython finds a python interpreter absolute path (python3 preferred).
// WindowsApps 里的 python3 是商店占位程序，执行会失败，不当成可用解释器。
func detectPython() string {
	for _, c := range []string{"python3", "python"} {
		p, err := exec.LookPath(c)
		if err != nil {
			continue
		}
		if runtime.GOOS == "windows" && strings.Contains(strings.ToLower(p), "windowsapps") {
			continue
		}
		return p
	}
	return ""
}

// pythonInterpreter resolves the interpreter: user-set > stored auto-detect > live
// detect. "" only when truly none found.
func (s *Server) pythonInterpreter() string {
	if v, ok, _ := s.m.pg.GetSetting(settingPythonInterp); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return detectPython()
}

// seedPythonInterpreter stores the auto-detected interpreter on startup if unset
// (never clobbers a user-set value).
func (s *Server) seedPythonInterpreter() {
	if v, ok, _ := s.m.pg.GetSetting(settingPythonInterp); ok && strings.TrimSpace(v) != "" {
		return
	}
	if p := detectPython(); p != "" {
		_ = s.m.pg.SetSetting(settingPythonInterp, p)
		log.Printf("[custom-tool] 自动检测到 python 解释器: %s", p)
	}
}

// ---------- exec 规格 ----------

type commandExec struct {
	Command   string `json:"command"`
	TimeoutMs int    `json:"timeout_ms"`
}
type scriptExec struct {
	Code      string `json:"code"`
	TimeoutMs int    `json:"timeout_ms"`
}
type httpExec struct {
	Method            string            `json:"method"`
	URL               string            `json:"url"`
	Headers           map[string]string `json:"headers"`
	Body              string            `json:"body"`
	TimeoutMs         int               `json:"timeout_ms"`
	Proxy             string            `json:"proxy"`
	UseRecordingProxy bool              `json:"use_recording_proxy"`
}

func timeoutOr(ms, def int) time.Duration {
	if ms <= 0 {
		return time.Duration(def) * time.Millisecond
	}
	return time.Duration(ms) * time.Millisecond
}

// ---------- 通用工具构造 ----------

// customTools builds CoreTools for every user-defined (system=false) tool row.
// shell-kind tools are environment hints only — they surface in the Bash tool
// description via ToolResolve and do NOT create callable tool entries here.
func (s *Server) customTools() ([]actool.CoreTool, error) {
	rows, err := s.m.pg.ListCustomTools()
	if err != nil {
		return nil, err
	}
	out := make([]actool.CoreTool, 0, len(rows))
	for _, t := range rows {
		if t.Kind == "shell" {
			continue // shell hints are handled by ToolResolve → Bash description
		}
		out = append(out, s.buildCustomTool(t))
	}
	return out, nil
}

// buildCustomTool turns one custom-tool row into a CoreTool. Empty schema → a thin
// {args:string} (薄壳工具), so command/http templates can use {args}.
func (s *Server) buildCustomTool(t *db.Tool) actool.CoreTool {
	schema := ensureSchema(t.Schema)
	key, kind, execRaw := t.Key, t.Kind, t.Exec
	run := func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
		var params map[string]any
		if len(in) > 0 {
			_ = json.Unmarshal(in, &params)
		}
		if params == nil {
			params = map[string]any{}
		}
		switch kind {
		case "command":
			return s.runCommandTool(ctx, execRaw, params, tc)
		case "script":
			return s.runScriptTool(ctx, key, execRaw, params, tc)
		case "http":
			return s.runHTTPTool(ctx, execRaw, params, tc)
		default:
			return actool.Errorf("未知自定义工具类型: " + kind), nil
		}
	}
	return actool.Build(actool.Spec{
		Name: key, Description: t.Description, Schema: schema,
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: run,
	})
}

// hasSchemaProps reports whether raw is a JSON-Schema object with ≥1 property.
// http tools require an explicit schema (the auto {args} shell can't name the
// {param} placeholders in URL/headers/body), so an empty schema is rejected.
func hasSchemaProps(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	props, _ := m["properties"].(map[string]any)
	return len(props) > 0
}

// ensureSchema returns the tool's schema, or a thin {args:string} when none given.
func ensureSchema(raw json.RawMessage) map[string]any {
	var m map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &m)
	}
	props, _ := m["properties"].(map[string]any)
	if len(props) > 0 {
		return m
	}
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"args": map[string]any{"type": "string", "description": "命令/参数(自由文本)"},
		},
	}
}

// ---------- command:渲染命令 → 复用 Bash 底层 run ----------

func (s *Server) runCommandTool(ctx context.Context, execRaw json.RawMessage, params map[string]any, tc *actool.ToolContext) (actool.Result, error) {
	var spec commandExec
	_ = json.Unmarshal(execRaw, &spec)
	if strings.TrimSpace(spec.Command) == "" {
		return actool.Errorf("command 为空"), nil
	}
	var skillDir, dataDir, python, node string
	if strings.Contains(spec.Command, "{{ARTEX_SKILL_DIR}}") {
		skillDir = commandDirectory(s.skillDir)
	}
	if strings.Contains(spec.Command, "{{ARTEX_DATA_DIR}}") {
		dataDir = commandDirectory(s.m.dir)
	}
	if strings.Contains(spec.Command, "{{ARTEX_PYTHON}}") {
		python = s.pythonInterpreter()
	}
	if strings.Contains(spec.Command, "{{ARTEX_NODE}}") {
		node = s.nodeInterpreter()
	}
	cmd, err := expandCommandPlaceholders(spec.Command, commandPlaceholderValues{
		SkillDir: skillDir, DataDir: dataDir, Python: python, Node: node,
	}, params)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	// 复用 Bash 也在用的底层 run(经 Bash CoreTool.Call):自动继承安全 floor/超时/
	// 代理 env/输出溢出。工具与 Bash 平级、共用底层,不经过 Bash 这个工具让模型调。
	bashIn, _ := json.Marshal(map[string]any{"command": cmd})
	if spec.TimeoutMs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeoutOr(spec.TimeoutMs, 120000))
		defer cancel()
	}
	return actool.NewBash().Call(ctx, bashIn, tc)
}

// ---------- script(仅 Python):临时文件 + stdin JSON + env ----------

func (s *Server) runScriptTool(ctx context.Context, key string, execRaw json.RawMessage, params map[string]any, tc *actool.ToolContext) (actool.Result, error) {
	var spec scriptExec
	_ = json.Unmarshal(execRaw, &spec)
	if strings.TrimSpace(spec.Code) == "" {
		return actool.Errorf("script code 为空"), nil
	}
	interp := s.pythonInterpreter()
	if interp == "" {
		return actool.Errorf("未配置且未检测到 python 解释器(在系统配置里设置)"), nil
	}
	workDir := s.m.dir
	var sessionEnv []string
	if tc != nil {
		if tc.WorkingDir != "" {
			workDir = tc.WorkingDir
		}
		sessionEnv = tc.Env
	}
	body, err := execPython(ctx, interp, key, spec.Code, params, workDir, sessionEnv, timeoutOr(spec.TimeoutMs, 120000))
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	return actool.Text(actool.Capture(tc, body)), nil
}

// execPython writes the code to a temp .py under workDir/.tools, runs it via interp
// with the params JSON on stdin + scalar params mirrored to TOOL_<NAME> env, and
// returns combined stdout+stderr (with a timeout/exit note). Standalone + testable.
func execPython(ctx context.Context, interp, key, code string, params map[string]any, workDir string, sessionEnv []string, timeout time.Duration) (string, error) {
	toolsDir := filepath.Join(workDir, ".tools")
	if err := os.MkdirAll(toolsDir, 0o755); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(toolsDir, key+"-*.py")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.WriteString(code); err != nil {
		f.Close()
		return "", err
	}
	f.Close()

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c := exec.CommandContext(runCtx, interp, tmp)
	c.Dir = workDir
	c.Env = append(os.Environ(), sessionEnv...) // 会话代理 env
	for k, v := range params {                  // 标量参数镜像成 TOOL_<NAME>
		if sv, ok := scalarStr(v); ok {
			c.Env = append(c.Env, "TOOL_"+strings.ToUpper(k)+"="+sv)
		}
	}
	pj, _ := json.Marshal(params)
	c.Stdin = bytes.NewReader(pj) // 参数 JSON 走 stdin
	out, err := c.CombinedOutput()
	body := string(out)
	if runCtx.Err() == context.DeadlineExceeded {
		body += "\n... [超时终止] ..."
	} else if err != nil {
		body += "\n[exit: " + err.Error() + "]"
	}
	return body, nil
}

// ---------- http:原生请求 + 代理 ----------

func (s *Server) runHTTPTool(ctx context.Context, execRaw json.RawMessage, params map[string]any, tc *actool.ToolContext) (actool.Result, error) {
	var spec httpExec
	_ = json.Unmarshal(execRaw, &spec)
	method := strings.ToUpper(strings.TrimSpace(spec.Method))
	if method == "" {
		method = "GET"
	}
	rawURL := renderTemplate(spec.URL, params, identity)
	if strings.TrimSpace(rawURL) == "" {
		return actool.Errorf("http url 为空"), nil
	}
	var bodyReader io.Reader
	if spec.Body != "" {
		bodyReader = strings.NewReader(renderTemplate(spec.Body, params, identity))
	}
	runCtx, cancel := context.WithTimeout(ctx, timeoutOr(spec.TimeoutMs, 30000))
	defer cancel()
	req, err := http.NewRequestWithContext(runCtx, method, rawURL, bodyReader)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	for k, v := range spec.Headers {
		req.Header.Set(k, renderTemplate(v, params, identity))
	}
	client := &http.Client{Timeout: timeoutOr(spec.TimeoutMs, 30000)}
	if tr := s.httpProxyTransport(spec); tr != nil {
		client.Transport = tr
	}
	resp, err := client.Do(req)
	if err != nil {
		return actool.Errorf("请求失败: " + err.Error()), nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	out := map[string]any{"status": resp.StatusCode, "body": string(respBody)}
	b, _ := json.Marshal(out)
	return actool.Text(actool.Capture(tc, string(b))), nil
}

// httpProxyTransport builds a Transport for the http tool's proxy config, or nil
// (direct). use_recording_proxy routes through the recording proxy + trusts its CA.
func (s *Server) httpProxyTransport(spec httpExec) *http.Transport {
	proxyStr := strings.TrimSpace(spec.Proxy)
	var caFile string
	if spec.UseRecordingProxy {
		if addr := s.m.ProxyAddr(); addr != "" {
			proxyStr = "http://" + addr
			caFile = s.m.ProxyCACert()
		}
	}
	if proxyStr == "" {
		return nil
	}
	pu, err := url.Parse(proxyStr)
	if err != nil {
		return nil
	}
	tr := &http.Transport{Proxy: http.ProxyURL(pu)}
	if caFile != "" {
		if pem, err := os.ReadFile(caFile); err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(pem) {
				tr.TLSClientConfig = &tls.Config{RootCAs: pool}
			}
		}
	}
	return tr
}

// ---------- helpers ----------

func identity(s string) string { return s }

// shellQuote single-quotes a value for safe shell interpolation.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

var (
	commandPlaceholder = regexp.MustCompile(`\{\{[^{}]*\}\}`)
	commandConditional = regexp.MustCompile(`\{\{IF ([A-Za-z_][A-Za-z0-9_]*)\}\}((?s:.*?))\{\{END\}\}`)
	// commandConditionalStart 只匹配条件块的开标记，用于校验模板里的占位符。
	commandConditionalStart = regexp.MustCompile(`^\{\{IF [A-Za-z_][A-Za-z0-9_]*\}\}$`)
)

// commandPlaceholderValues 是模板里固名占位符的替换值（都已 shell 转义前）。
type commandPlaceholderValues struct {
	SkillDir string
	DataDir  string
	Python   string
	Node     string
}

// expandCommandPlaceholders 先展开 {{IF <param>}}…{{END}} 条件块，再替换固名占位符，
// 最后把剩下的段交给 renderTemplate 处理 {param}。未知 {{X}} 原样保留，避免破坏
// 用户自己写的模板。
//
// 条件块只支持一层、不支持嵌套：<param> 存在且不是 false/0/空串时保留块内容，
// 否则整块删除。用于「可选参数才追加某个 flag」这类常见需要（例如 --seed、
// --host-mode、--dry-run）。
func expandCommandPlaceholders(cmd string, v commandPlaceholderValues, params map[string]any) (string, error) {
	cmd = commandConditional.ReplaceAllStringFunc(cmd, func(block string) string {
		m := commandConditional.FindStringSubmatch(block)
		if len(m) != 3 {
			return block
		}
		if truthyParam(params, m[1]) {
			return m[2]
		}
		return ""
	})
	var out strings.Builder
	start := 0
	for _, loc := range commandPlaceholder.FindAllStringIndex(cmd, -1) {
		out.WriteString(renderTemplate(cmd[start:loc[0]], params, shellQuote))
		token := cmd[loc[0]:loc[1]]
		switch token {
		case "{{ARTEX_SKILL_DIR}}":
			if v.SkillDir == "" {
				return "", fmt.Errorf("技能目录未配置，无法运行脚本工具")
			}
			out.WriteString(shellQuote(v.SkillDir))
		case "{{ARTEX_DATA_DIR}}":
			if v.DataDir == "" {
				return "", fmt.Errorf("数据目录未配置，无法运行脚本工具")
			}
			out.WriteString(shellQuote(v.DataDir))
		case "{{ARTEX_PYTHON}}":
			if v.Python == "" {
				return "", fmt.Errorf("未检测到 python 解释器（在系统设置里配置 python_interpreter）")
			}
			out.WriteString(shellQuote(v.Python))
		case "{{ARTEX_NODE}}":
			if v.Node == "" {
				return "", fmt.Errorf("未检测到 node（在系统设置里配置 node_interpreter）")
			}
			out.WriteString(shellQuote(v.Node))
		default:
			out.WriteString(token)
		}
		start = loc[1]
	}
	out.WriteString(renderTemplate(cmd[start:], params, shellQuote))
	return out.String(), nil
}

// truthyParam 判断条件块用的参数是否"有值"：缺省、nil、空串、false、0 都算无值。
func truthyParam(params map[string]any, name string) bool {
	v, ok := params[name]
	if !ok || v == nil {
		return false
	}
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x) != ""
	case bool:
		return x
	case float64:
		return x != 0
	case int:
		return x != 0
	case int64:
		return x != 0
	default:
		return true
	}
}

// commandDirectory resolves a configured directory for shell interpolation.
// Empty, inaccessible and non-directory paths all map to an unset directory.
func commandDirectory(dir string) string {
	if strings.TrimSpace(dir) == "" {
		return ""
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	if info, err := os.Stat(abs); err != nil || !info.IsDir() {
		return ""
	}
	return abs
}

// renderTemplate replaces {name} placeholders with each param's rendered value.
func renderTemplate(tmpl string, params map[string]any, quote func(string) string) string {
	out := tmpl
	for k, v := range params {
		out = strings.ReplaceAll(out, "{"+k+"}", quote(valToStr(v)))
	}
	return out
}

// valToStr renders a param value: scalars as-is, arrays/objects as compact JSON.
func valToStr(v any) string {
	if sv, ok := scalarStr(v); ok {
		return sv
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// scalarStr returns (string, true) for scalar values, ("", false) for arrays/objects.
func scalarStr(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case bool:
		return fmt.Sprintf("%t", x), true
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x)), true
		}
		return fmt.Sprintf("%g", x), true
	case nil:
		return "", true
	default:
		return "", false
	}
}
