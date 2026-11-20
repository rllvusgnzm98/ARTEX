package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func captureDoctor(t *testing.T, args ...string) (out string, code int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	code = runDoctor(args)
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	return buf.String(), code
}

func isolateConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfg, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_CONFIG", cfg)
	t.Setenv("ARTEX_CALLBACK_ADDR", "")
	t.Setenv("ARTEX_GATE_MODE", "")
	t.Setenv("ARTEX_GATE", "")
	return dir
}

func TestIsDoctorCommandBeforeFlags(t *testing.T) {
	if !isDoctorCommand([]string{"artex", "doctor"}) {
		t.Fatal("artex doctor 应在 flag 解析前被识别")
	}
	if !isDoctorCommand([]string{"artex", "doctor", "-addr", ":8787"}) {
		t.Fatal("带 flag 的 doctor 仍应分流")
	}
	if isDoctorCommand([]string{"artex"}) || isDoctorCommand([]string{"artex", "-addr", ":8787"}) {
		t.Fatal("服务启动参数不应被当成 doctor")
	}
}

func TestDoctorDefaultAddrIsAllInterfaces(t *testing.T) {
	if doctorDefaultAddr != ":8787" {
		t.Fatalf("doctor -addr 默认必须是 :8787，got %q", doctorDefaultAddr)
	}
}

func TestRunDoctorMissingManifestDoesNotFail(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("ARTEX_PG_DSN"))
	if dsn == "" {
		t.Skip("no ARTEX_PG_DSN — skipping doctor integration")
	}
	isolateConfig(t)
	t.Setenv("ARTEX_PG_DSN", dsn)
	t.Setenv("ARTEX_TOOLS_MANIFEST", filepath.Join(t.TempDir(), "missing-manifest.json"))
	data := t.TempDir()
	out, code := captureDoctor(t, "-data", data, "-addr", ":8787")
	if code != 0 {
		t.Fatalf("清单缺失不应把平台判死, exit=%d\n%s", code, out)
	}
	if !strings.Contains(out, "工具清单") || !strings.Contains(out, "WARN") {
		t.Fatalf("清单缺失应警告并跳过汇总:\n%s", out)
	}
	if strings.Contains(out, "suo5-payloads") {
		t.Fatalf("缺省回退不得检查 suo5-payloads:\n%s", out)
	}
	if strings.Contains(out, "门控将默认开启") || strings.Contains(out, "非 loopback 时默认开启") {
		t.Fatalf("不得出现非 loopback 自动门控文案:\n%s", out)
	}
	if strings.Contains(out, "本波未启用") {
		t.Fatalf("不得再使用未实现占位文案:\n%s", out)
	}
	if !strings.Contains(out, "mode=") || !strings.Contains(out, "来源=") || !strings.Contains(out, "探测计数") {
		t.Fatalf("门控应报告 mode、来源和探测计数:\n%s", out)
	}
	if !strings.Contains(out, "暴露全网卡") || !strings.Contains(out, "服务未运行") {
		t.Fatalf("默认地址应报告暴露全网卡，且无统计文件时说明服务未运行:\n%s", out)
	}
	if strings.Contains(out, "backend listening") {
		t.Fatal("doctor 不得启动服务")
	}
	if !strings.Contains(out, "只读，不启动服务、不写 DB") {
		t.Fatalf("应声明只读预检:\n%s", out)
	}
}

func TestRunDoctorMissingToolsAreWarn(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("ARTEX_PG_DSN"))
	if dsn == "" {
		t.Skip("no ARTEX_PG_DSN — skipping doctor integration")
	}
	isolateConfig(t)
	t.Setenv("ARTEX_PG_DSN", dsn)
	man := filepath.Join(t.TempDir(), "tools-manifest.json")
	body := `{"tools":[{"name":"chisel","path":"tools/chisel","env":"ARTEX_CHISEL_PATH","category":"tunnel","sha256":""}]}`
	if err := os.WriteFile(man, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_TOOLS_MANIFEST", man)
	out, code := captureDoctor(t, "-data", t.TempDir())
	if code != 0 {
		t.Fatalf("隧道缺失应为 WARN 而不是 FAIL, exit=%d\n%s", code, out)
	}
	if !strings.Contains(out, "chisel 缺失") || !strings.Contains(out, "[WARN] 隧道工具") {
		t.Fatalf("隧道缺失应记 WARN:\n%s", out)
	}
}

func TestRunDoctorFailWhenDataNotDir(t *testing.T) {
	isolateConfig(t)
	t.Setenv("ARTEX_PG_DSN", "")
	t.Setenv("ARTEX_TOOLS_MANIFEST", filepath.Join(t.TempDir(), "nope.json"))
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := captureDoctor(t, "-data", file)
	if code != 1 {
		t.Fatalf("data 不是目录应为 FAIL 且退出 1, exit=%d\n%s", code, out)
	}
	if !strings.Contains(out, "[FAIL] data 目录") {
		t.Fatalf("应出现 data 目录 FAIL:\n%s", out)
	}
}

func TestReadEnvFileValue(t *testing.T) {
	p := filepath.Join(t.TempDir(), "artex.env")
	content := "# comment\nARTEX_CALLBACK_ADDR=\"10.0.0.2:8080\"\nOTHER=1\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	v, ok := readEnvFileValue(p, "ARTEX_CALLBACK_ADDR")
	if !ok || v != "10.0.0.2:8080" {
		t.Fatalf("got %q ok=%v", v, ok)
	}
	if _, ok := readEnvFileValue(p, "MISSING"); ok {
		t.Fatal("missing key should be ok=false")
	}
}

func TestDockerfileAPTMirrorDefaultEmpty(t *testing.T) {
	candidates := []string{"Dockerfile", filepath.Join("..", "..", "Dockerfile")}
	var raw []byte
	var err error
	for _, p := range candidates {
		raw, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, "FROM python:3.12-slim-bookworm") {
		t.Fatal("应保留 ours 运行镜像，而不是换成 Dockerfile.source")
	}
	if !strings.Contains(s, "ARG APT_MIRROR=") {
		t.Fatal("缺少 ARG APT_MIRROR=")
	}
	// 默认必须是空：ARG APT_MIRROR= 后不应跟非空默认值
	if strings.Contains(s, "ARG APT_MIRROR=http") || strings.Contains(s, "ARG APT_MIRROR=mirrors") {
		t.Fatal("APT_MIRROR 默认必须为空")
	}
	idxMirror := strings.Index(s, "ARG APT_MIRROR=")
	idxApt := strings.Index(s, "apt-get update")
	if idxMirror < 0 || idxApt < 0 || idxMirror > idxApt {
		t.Fatal("APT_MIRROR 必须在 apt-get update 之前声明")
	}
	if !strings.Contains(s, `if [ -n "$APT_MIRROR" ]`) {
		t.Fatal("只有非空时才应换源")
	}
}

func TestSystemdUnitListensOnAllInterfaces(t *testing.T) {
	candidates := []string{
		filepath.Join("packaging", "artex.service"),
		filepath.Join("..", "..", "packaging", "artex.service"),
	}
	var raw []byte
	var err error
	for _, p := range candidates {
		raw, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, "ExecStart=/opt/artex/artex -addr :8787 -proxy 127.0.0.1:8788") {
		t.Fatalf("systemd ExecStart 必须是 -addr :8787 -proxy 127.0.0.1:8788:\n%s", s)
	}
	if strings.Contains(s, "-addr 127.0.0.1:8787") {
		t.Fatal("systemd 不得把监听改成 127.0.0.1:8787")
	}
	if strings.Contains(s, "-proxy :8788") {
		t.Fatal("流量录制代理不得绑到全网卡 :8788")
	}
}

func TestDockerfileProxyBindsLoopback(t *testing.T) {
	candidates := []string{"Dockerfile", filepath.Join("..", "..", "Dockerfile")}
	var raw []byte
	var err error
	for _, p := range candidates {
		raw, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	want := `CMD ["-addr", ":8787", "-proxy", "127.0.0.1:8788"]`
	if !strings.Contains(s, want) {
		t.Fatalf("Dockerfile CMD 必须是 %s", want)
	}
	if strings.Contains(s, `"-proxy", ":8788"`) {
		t.Fatal("Dockerfile 流量录制代理不得绑到全网卡 :8788")
	}
	if strings.Contains(s, `"-addr", "127.0.0.1:8787"`) {
		t.Fatal("Dockerfile 不得把 -addr 改成 127.0.0.1:8787")
	}
}

func TestRunDoctorArsenalHashMismatchIsWarn(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("ARTEX_PG_DSN"))
	if dsn == "" {
		t.Skip("no ARTEX_PG_DSN — skipping doctor integration")
	}
	isolateConfig(t)
	t.Setenv("ARTEX_PG_DSN", dsn)
	data := t.TempDir()
	if err := os.MkdirAll(filepath.Join(data, "tools"), 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(data, "tools", "demo-tool")
	if err := os.WriteFile(bin, []byte("fixture-bytes-not-matching-pin"), 0o755); err != nil {
		t.Fatal(err)
	}
	// 非空假哈希，与文件内容必然不匹配；只作夹具，不是真实密钥。
	pinned := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	man := filepath.Join(t.TempDir(), "tools-manifest.json")
	body := `{"tools":[{"name":"demo-tool","path":"tools/demo-tool","category":"arsenal","sha256":"` + pinned + `"}]}`
	if err := os.WriteFile(man, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_TOOLS_MANIFEST", man)
	out, code := captureDoctor(t, "-data", data)
	if code != 0 {
		t.Fatalf("军火库哈希不匹配只应 WARN、不得 FAIL, exit=%d\n%s", code, out)
	}
	if !strings.Contains(out, "[WARN] 军火库工具") || !strings.Contains(out, "哈希不匹配") {
		t.Fatalf("军火库汇总应为 WARN 且文案能看出哈希不匹配:\n%s", out)
	}
	if strings.Contains(out, "[OK] 军火库工具") {
		t.Fatalf("哈希不匹配不得打 OK:\n%s", out)
	}
	if strings.Contains(out, "存在 1/1") {
		t.Fatalf("哈希不匹配不得算进「存在 N/N」:\n%s", out)
	}
}

func TestDoctorCLIDoesNotStartServer(t *testing.T) {
	isolateConfig(t)
	t.Setenv("ARTEX_PG_DSN", "")
	bin := filepath.Join(t.TempDir(), "artex")
	if runtime.GOOS == "windows" {
		// 无 .exe 后缀时，Windows 的 os/exec 不会把绝对路径当成可执行文件。
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, "github.com/Autumn-27/artex/cmd/artex")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	data := t.TempDir()
	cmd := exec.Command(bin, "doctor", "-data", data, "-addr", ":8787")
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	text := string(out)
	if strings.Contains(text, "backend listening") || strings.Contains(text, "open stores") {
		t.Fatalf("doctor 在 flag 解析前分流失败，似乎启动了服务:\n%s", text)
	}
	if !strings.Contains(text, "部署预检") {
		t.Fatalf("应跑 doctor 预检:\n%s", text)
	}
	if err == nil {
		// 无 DSN 时期望 FAIL→退出 1；若环境意外有库配置则可能是 0。
		return
	}
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 {
		t.Fatalf("无库配置时 doctor 应退出 1, err=%v\n%s", err, text)
	}
}

func TestDoctorReportsResolvedGate(t *testing.T) {
	isolateConfig(t)
	t.Setenv("ARTEX_PG_DSN", "")
	t.Setenv("ARTEX_GATE_MODE", "enforce")
	t.Setenv("ARTEX_GATE", "0")
	out, code := captureDoctor(t, "-data", t.TempDir(), "-addr", "127.0.0.1:8787")
	if code != 1 {
		t.Fatalf("无数据库应 FAIL, exit=%d\n%s", code, out)
	}
	if !strings.Contains(out, "mode=enforce") || !strings.Contains(out, "来源=env") {
		t.Fatalf("env 应压过 legacy，got:\n%s", out)
	}
	if !strings.Contains(out, "仅本机回环") {
		t.Fatalf("回环监听应被识别:\n%s", out)
	}
	if !strings.Contains(out, "服务未运行") {
		t.Fatalf("无统计文件应说明服务未运行:\n%s", out)
	}
	if strings.Contains(out, "命中 0") {
		t.Fatalf("读不到计数时不得编造零:\n%s", out)
	}
	if strings.Contains(out, "门控将默认开启") || strings.Contains(out, "非 loopback 时默认开启") {
		t.Fatalf("不得出现自动开门控文案:\n%s", out)
	}
}

func TestDoctorReadsGateStatsFile(t *testing.T) {
	isolateConfig(t)
	t.Setenv("ARTEX_PG_DSN", "")
	data := t.TempDir()
	if err := os.MkdirAll(filepath.Join(data, "gate"), 0o700); err != nil {
		t.Fatal(err)
	}
	body := `{"mode":"detect","source":"default","hits":3,"allows":2,"bypasses":1,"decoys":1,"updated_at":"2026-01-02T03:04:05Z"}`
	if err := os.WriteFile(filepath.Join(data, "gate", "stats.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _ := captureDoctor(t, "-data", data, "-addr", ":8787")
	if !strings.Contains(out, "命中 3") || !strings.Contains(out, "放行 2") || !strings.Contains(out, "旁路 1") || !strings.Contains(out, "诱饵 1") {
		t.Fatalf("应读到统计文件里的计数:\n%s", out)
	}
	if !strings.Contains(out, "2026-01-02T03:04:05Z") {
		t.Fatalf("应读到统计文件里的更新时间:\n%s", out)
	}
	if strings.Contains(out, "服务未运行") {
		t.Fatalf("有统计文件时不得说服务未运行:\n%s", out)
	}
}

func TestDoctorGatePathNotDir(t *testing.T) {
	isolateConfig(t)
	t.Setenv("ARTEX_PG_DSN", "")
	data := t.TempDir()
	if err := os.WriteFile(filepath.Join(data, "gate"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _ := captureDoctor(t, "-data", data)
	if !strings.Contains(out, "[WARN] 伪装门控") || !strings.Contains(out, "不是目录") {
		t.Fatalf("data/gate 不是目录应 WARN:\n%s", out)
	}
}
