package main

import (
	"bytes"
	"encoding/json"
	"github.com/Autumn-27/artex/agent"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/server"
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
	if runtime.GOOS != "windows" {
		bin := t.TempDir()
		for _, seed := range agent.ShellHintSeeds() {
			if seed.Key == "nxc" {
				continue
			}
			if err := os.WriteFile(filepath.Join(bin, seed.Key), []byte("#!/bin/sh\necho projectdiscovery.io version-test\n"), 0755); err != nil {
				t.Fatal(err)
			}
		}
		t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
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
	if strings.Contains(s, "setup_$${node_major}") {
		t.Fatal("NodeSource URL must expand the version, not the shell PID")
	}
	if !strings.Contains(s, "path-include /usr/share/doc/python3-impacket/*") {
		t.Fatal("slim images must retain Impacket example entry points")
	}
	if !strings.Contains(s, "exec /usr/bin/python3 /usr/share/doc/python3-impacket/examples/") || !strings.Contains(s, `"/usr/local/bin/impacket-$name" -h`) {
		t.Fatal("Impacket commands must use Debian Python and smoke-test imports")
	}
	if !strings.Contains(s, "COPY packaging/tools-manifest.json packaging/image-tools.json /app/packaging/") {
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

func buildArtexCLI(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "artex")
	// Windows os/exec 只接受 PATHEXT 里的扩展名。不带 .exe 时能编出来，但跑不起来。
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, "github.com/Autumn-27/artex/cmd/artex")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

func TestDoctorCLIDoesNotStartServer(t *testing.T) {
	isolateConfig(t)
	t.Setenv("ARTEX_PG_DSN", "")
	bin := buildArtexCLI(t)
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

func TestDatabaseFailureDiagnosticsDoNotEchoDSN(t *testing.T) {
	bin := buildArtexCLI(t)
	for _, tt := range []struct {
		name, dsn, reason string
		secrets           []string
	}{
		{"percent-space", "postgres://artex@127.0.0.1:1/postgres?password=PW%20SPACE&sslmode=bogus",
			"invalid PostgreSQL DSN", []string{"PW%20SPACE", "PW SPACE", "PW+SPACE"}},
		{"percent-unreserved", "postgres://artex@127.0.0.1:1/postgres?password=PW%61TAIL&sslmode=bogus",
			"invalid PostgreSQL DSN", []string{"PW%61TAIL", "PWaTAIL"}},
		{"invalid-url-port", "postgres://artex:PW-INVALID-PORT@127.0.0.1:invalid/postgres",
			"invalid PostgreSQL DSN", []string{"PW-INVALID-PORT"}},
		{"keyword-escaped-whitespace", `host=127.0.0.1 port=1 dbname=postgres user=artex password=PW\ TAIL-CANARY sslmode=disable connect_timeout=1`,
			"PostgreSQL connection refused", []string{"PW\\ TAIL-CANARY", "PW TAIL-CANARY", "TAIL-CANARY"}},
		{"ssl-key-password", "postgres://artex@127.0.0.1:1/postgres?sslpassword=PW-SSL-KEY&sslmode=bogus",
			"invalid PostgreSQL DSN", []string{"PW-SSL-KEY"}},
		{"query-password", "postgres://artex@127.0.0.1:1/postgres?password=PW-QUERY&sslmode=bogus",
			"invalid PostgreSQL DSN", []string{"PW-QUERY"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := isolateConfig(t)
			fileConfig, err := json.Marshal(map[string]map[string]string{"database": {"dsn": tt.dsn}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "config.json"), fileConfig, 0o600); err != nil {
				t.Fatal(err)
			}
			data := t.TempDir()
			for _, cli := range []struct {
				name, envDSN, prefix string
				args                 []string
			}{
				{"startup", tt.dsn, "open stores: ", []string{"-data", data, "-proxy", ""}},
				{"doctor", tt.dsn, "[FAIL] PostgreSQL: ", []string{"doctor", "-data", data}},
				{"doctor-strict", "", "[FAIL] PostgreSQL: ", []string{"doctor", "-strict-tools", "-data", data}},
			} {
				t.Run(cli.name, func(t *testing.T) {
					t.Setenv("ARTEX_PG_DSN", cli.envDSN)
					out, err := exec.Command(bin, cli.args...).CombinedOutput()
					if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 {
						t.Fatalf("expected database failure exit 1; got %v", err)
					}
					output := string(out)
					for _, unsafe := range append(tt.secrets, tt.dsn, "postgres://", "host=127.0.0.1", "cannot parse", "failed to connect") {
						if strings.Contains(output, unsafe) {
							t.Fatal("output leaked the DSN, a password fragment, or a raw pgx error")
						}
					}
					_, diagnostic, found := strings.Cut(output, cli.prefix)
					reason, _, _ := strings.Cut(diagnostic, "\n")
					if !found || reason != tt.reason {
						t.Fatalf("expected a database diagnostic with only %q", tt.reason)
					}
				})
			}
		})
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

// doctorHackbotsTests 把脚本目录指到临时目录，避免依赖真实 skills/ 内容。
func writeDoctorScripts(t *testing.T, skillDir string, count int) {
	t.Helper()
	paths := server.HackbotsScriptPaths()
	if len(paths) == 0 {
		t.Fatal("Hackbots 工具清单为空")
	}
	if count > len(paths) {
		count = len(paths)
	}
	for _, rel := range paths[:count] {
		full := filepath.Join(skillDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// 技能目录整体不存在 = 本次部署没带技能包：SKIP，且 strict 也不得升级为 FAIL，
// 否则没装技能包的部署会被预检判死。
func TestDoctorHackbotsMissingSkillDirIsSkip(t *testing.T) {
	dsn, ok := isolateDoctorDB(t)
	if !ok {
		return
	}
	t.Setenv("ARTEX_PG_DSN", dsn)
	t.Setenv("ARTEX_SKILL_DIR", filepath.Join(t.TempDir(), "absent"))
	out, code := captureDoctor(t, "-data", t.TempDir(), "-strict-tools")
	if code != 0 {
		t.Fatalf("技能目录缺失不得 FAIL, exit=%d\n%s", code, out)
	}
	if !strings.Contains(out, "[SKIP] Hackbots 工具") || !strings.Contains(out, "技能目录不存在") {
		t.Fatalf("技能目录缺失应 SKIP:\n%s", out)
	}
}

// 目录在但脚本缺失：默认 WARN，-strict-tools 下 FAIL。
func TestDoctorHackbotsMissingScripts(t *testing.T) {
	dsn, ok := isolateDoctorDB(t)
	if !ok {
		return
	}
	t.Setenv("ARTEX_PG_DSN", dsn)
	skillDir := t.TempDir()
	t.Setenv("ARTEX_SKILL_DIR", skillDir)
	out, code := captureDoctor(t, "-data", t.TempDir())
	if code != 0 {
		t.Fatalf("默认脚本缺失应为 WARN, exit=%d\n%s", code, out)
	}
	if !strings.Contains(out, "[WARN] Hackbots 工具") || !strings.Contains(out, "缺失: ") {
		t.Fatalf("脚本缺失应 WARN 并列出缺失项:\n%s", out)
	}

	out, code = captureDoctor(t, "-data", t.TempDir(), "-strict-tools")
	if code != 1 {
		t.Fatalf("strict 下脚本缺失应 FAIL, exit=%d\n%s", code, out)
	}
	if !strings.Contains(out, "[FAIL] Hackbots 工具") {
		t.Fatalf("strict 应报 FAIL:\n%s", out)
	}
}

// 脚本齐全时不得再报缺失（解释器是否装好由机器决定，只断言脚本计数）。
func TestDoctorHackbotsScriptsPresent(t *testing.T) {
	dsn, ok := isolateDoctorDB(t)
	if !ok {
		return
	}
	t.Setenv("ARTEX_PG_DSN", dsn)
	skillDir := t.TempDir()
	t.Setenv("ARTEX_SKILL_DIR", skillDir)
	writeDoctorScripts(t, skillDir, len(server.HackbotsScriptPaths()))
	out, _ := captureDoctor(t, "-data", t.TempDir())
	total := len(server.HackbotsScriptPaths())
	if !strings.Contains(out, "脚本 "+strconv.Itoa(total)+"/"+strconv.Itoa(total)+" 存在") {
		t.Fatalf("脚本齐全时应报告 %d/%d:\n%s", total, total, out)
	}
	if strings.Contains(out, "缺失: ") {
		t.Fatalf("脚本齐全时不得报缺失:\n%s", out)
	}
}

// isolateDoctorDB 复用当前 ARTEX_PG_DSN：Hackbots 项只在数据库可连接时才不会被
// PostgreSQL 的 FAIL 掩盖退出码。没有数据库时跳过（与其它 doctor 集成测试一致）。
// 同时把外部工具清单指到空清单，避免隧道工具缺失干扰 Hackbots 项的断言。
func isolateDoctorDB(t *testing.T) (string, bool) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("ARTEX_PG_DSN"))
	if dsn == "" {
		t.Skip("no ARTEX_PG_DSN — skipping doctor integration")
		return "", false
	}
	isolateConfig(t)
	man := filepath.Join(t.TempDir(), "tools-manifest.json")
	if err := os.WriteFile(man, []byte(`{"tools":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_TOOLS_MANIFEST", man)
	return dsn, true
}
