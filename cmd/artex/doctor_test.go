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
	if !strings.Contains(out, "本波未启用") || !strings.Contains(out, "ARTEX_GATE=1") {
		t.Fatalf("门控提示应说明本波未启用且需显式 opt-in:\n%s", out)
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
	for _, arg := range []string{
		"ARG NODE_MAJOR=",
		"ARG NODESOURCE_URL=",
		"ARG NPM_REGISTRY=",
		"ARG PLAYWRIGHT_DOWNLOAD_HOST=",
	} {
		if !strings.Contains(s, arg) {
			t.Fatalf("缺少 %s", arg)
		}
		if strings.Contains(s, arg+"http") || strings.Contains(s, arg+"20") || strings.Contains(s, arg+"mirrors") {
			t.Fatalf("%s 默认必须为空", arg)
		}
	}
	if !strings.Contains(s, "sources.list.bak") || !strings.Contains(s, "Acquire::Retries=3") {
		t.Fatal("apt 改源失败应备份 sources.list 并带 Acquire::Retries=3 回退")
	}
	if !strings.Contains(s, `if ! npm install -g --registry="$NPM_REGISTRY"`) {
		t.Fatal("npm 镜像安装失败应回退官方安装")
	}
	if !strings.Contains(s, "playwright install --with-deps chromium") {
		t.Fatal("应保留 Playwright 浏览器安装，并在镜像失败时回退")
	}
	if !strings.Contains(s, "COPY packaging/tools-manifest.json /app/packaging/tools-manifest.json") {
		t.Fatal("镜像应打包 packaging/tools-manifest.json")
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

func TestRunDoctorStrictToolsMissingNonOptionalFails(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("ARTEX_PG_DSN"))
	if dsn == "" {
		t.Skip("no ARTEX_PG_DSN — skipping doctor integration")
	}
	isolateConfig(t)
	t.Setenv("ARTEX_PG_DSN", dsn)
	man := filepath.Join(t.TempDir(), "tools-manifest.json")
	body := `{"tools":[{"name":"naabu","path":"tools/naabu","category":"arsenal","optional":false,"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}`
	if err := os.WriteFile(man, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_TOOLS_MANIFEST", man)
	out, code := captureDoctor(t, "-data", t.TempDir(), "-strict-tools")
	if code != 1 {
		t.Fatalf("-strict-tools 下非 optional 缺失应为 FAIL, exit=%d\n%s", code, out)
	}
	if !strings.Contains(out, "[FAIL] 军火库工具") || !strings.Contains(out, "缺失: naabu") {
		t.Fatalf("应 FAIL 并点名缺失工具:\n%s", out)
	}
}

func TestRunDoctorStrictToolsHashMismatchFails(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(data, "tools", "httpx"), []byte("present-but-wrong"), 0o755); err != nil {
		t.Fatal(err)
	}
	man := filepath.Join(t.TempDir(), "tools-manifest.json")
	body := `{"tools":[{"name":"httpx","path":"tools/httpx","category":"arsenal","optional":false,"sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}]}`
	if err := os.WriteFile(man, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_TOOLS_MANIFEST", man)
	out, code := captureDoctor(t, "-data", data, "-strict-tools")
	if code != 1 {
		t.Fatalf("-strict-tools 下非 optional 哈希不匹配应为 FAIL, exit=%d\n%s", code, out)
	}
	if !strings.Contains(out, "[FAIL] 军火库工具") || !strings.Contains(out, "哈希不匹配") {
		t.Fatalf("应 FAIL 并说明哈希不匹配:\n%s", out)
	}
}

func TestRunDoctorStrictToolsOptionalMissingStaysWarn(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("ARTEX_PG_DSN"))
	if dsn == "" {
		t.Skip("no ARTEX_PG_DSN — skipping doctor integration")
	}
	isolateConfig(t)
	t.Setenv("ARTEX_PG_DSN", dsn)
	man := filepath.Join(t.TempDir(), "tools-manifest.json")
	body := `{"tools":[{"name":"chisel","path":"tools/chisel","category":"tunnel","optional":true,"sha256":""}]}`
	if err := os.WriteFile(man, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_TOOLS_MANIFEST", man)
	out, code := captureDoctor(t, "-data", t.TempDir(), "-strict-tools")
	if code != 0 {
		t.Fatalf("optional 缺失在 -strict-tools 下仍应为 WARN, exit=%d\n%s", code, out)
	}
	if !strings.Contains(out, "[WARN] 隧道工具") || !strings.Contains(out, "chisel 缺失") {
		t.Fatalf("optional 缺失应继续 WARN:\n%s", out)
	}
	if strings.Contains(out, "[FAIL] 隧道工具") {
		t.Fatalf("optional 不得 FAIL:\n%s", out)
	}
}

func TestRunDoctorOtherPlatformIsSkip(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(data, "tools", "naabu"), []byte("local-bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	man := filepath.Join(t.TempDir(), "tools-manifest.json")
	// plan9 不是本机平台。文件在、哈希也故意不对，仍必须 SKIP 而不是 mismatch FAIL。
	body := `{"tools":[{"name":"naabu","path":"tools/naabu","category":"arsenal","platform":"plan9/amd64","optional":false,"sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}]}`
	if err := os.WriteFile(man, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_TOOLS_MANIFEST", man)
	out, code := captureDoctor(t, "-data", data, "-strict-tools")
	if code != 0 {
		t.Fatalf("平台不符不得 FAIL, exit=%d\n%s", code, out)
	}
	if !strings.Contains(out, "[SKIP] 军火库工具") || !strings.Contains(out, "不适用") {
		t.Fatalf("平台不符应 SKIP:\n%s", out)
	}
	if strings.Contains(out, "哈希不匹配") {
		t.Fatalf("平台不符不得报哈希不匹配:\n%s", out)
	}
}

func TestDoctorCLIDoesNotStartServer(t *testing.T) {
	isolateConfig(t)
	t.Setenv("ARTEX_PG_DSN", "")
	bin := filepath.Join(t.TempDir(), "artex")
	// Windows os/exec 只接受 PATHEXT 里的扩展名。不带 .exe 时能编出来，但跑不起来。
	if runtime.GOOS == "windows" {
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
