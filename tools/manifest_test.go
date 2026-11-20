package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func writeManifest(t *testing.T, entries []Entry) string {
	t.Helper()
	b, err := json.Marshal(Manifest{Tools: entries})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "tools-manifest.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadMissing(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if !os.IsNotExist(err) {
		t.Fatalf("缺失清单应满足 os.IsNotExist,得到 %v", err)
	}
}

func TestCheckStatuses(t *testing.T) {
	dataDir := t.TempDir()
	content := []byte("fake-binary")
	sum := sha256.Sum256(content)
	if err := os.WriteFile(filepath.Join(dataDir, "ok"), content, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "unpinned"), content, 0o700); err != nil {
		t.Fatal(err)
	}
	entries := []Entry{
		{Name: "ok", Path: "ok", SHA256: hex.EncodeToString(sum[:])},
		{Name: "unpinned", Path: "unpinned"},
		{Name: "missing", Path: "missing"},
		{Name: "mismatch", Path: "ok", SHA256: strings.Repeat("0", 64)},
	}
	m, err := Load(writeManifest(t, entries))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Status{}
	for _, r := range Check(m, dataDir) {
		got[r.Entry.Name] = r.Status
	}
	want := map[string]Status{
		"ok": StatusOK, "unpinned": StatusUnpinned,
		"missing": StatusMissing, "mismatch": StatusMismatch,
	}
	for name, ws := range want {
		if got[name] != ws {
			t.Errorf("%s: 期望状态 %v,得到 %v", name, ws, got[name])
		}
	}
}

func TestCheckEnvOverride(t *testing.T) {
	dataDir := t.TempDir()
	alt := filepath.Join(t.TempDir(), "custom-chisel")
	if err := os.WriteFile(alt, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_CHISEL_PATH", alt)
	r := CheckEntry(Entry{Name: "chisel", Path: "tools/chisel", Env: "ARTEX_CHISEL_PATH"}, dataDir)
	if r.Status != StatusUnpinned || r.Path != alt {
		t.Fatalf("env 覆盖未生效: status=%v path=%s", r.Status, r.Path)
	}
}

func TestEmptySHA256OnlyChecksExistence(t *testing.T) {
	dataDir := t.TempDir()
	p := filepath.Join(dataDir, "tools", "chisel")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("not-a-pinned-hash"), 0o700); err != nil {
		t.Fatal(err)
	}
	r := CheckEntry(Entry{Name: "chisel", Path: "tools/chisel", SHA256: ""}, dataDir)
	if r.Status != StatusUnpinned {
		t.Fatalf("未钉哈希应只查存在性, got %v", r.Status)
	}
}

func defaultManifestPath(t *testing.T) string {
	t.Helper()
	candidates := []string{
		"packaging/tools-manifest.json",
		filepath.Join("..", "packaging", "tools-manifest.json"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Fatal("找不到 packaging/tools-manifest.json")
	return ""
}

func TestLoadIgnoresUnknownFields(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tools-manifest.json")
	body := `{"tools":[{"name":"x","path":"tools/x","url":"https://example.invalid/x","optional":true,"license_note":"metadata only","future_field":1}]}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Tools) != 1 || m.Tools[0].URL != "https://example.invalid/x" || !m.Tools[0].Optional {
		t.Fatalf("未知字段不应导致解析失败: %+v", m.Tools)
	}
}

func TestCheckEntryOtherPlatformSkips(t *testing.T) {
	dataDir := t.TempDir()
	p := filepath.Join(dataDir, "tools", "naabu")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("not-the-pinned-bytes"), 0o700); err != nil {
		t.Fatal(err)
	}
	other := "linux/amd64"
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		other = "linux/arm64"
	}
	r := CheckEntry(Entry{
		Name: "naabu", Path: "tools/naabu", Platform: other,
		SHA256: strings.Repeat("ab", 32),
	}, dataDir)
	if r.Status != StatusNotApplicable {
		t.Fatalf("平台不符应跳过，不能假报 mismatch/missing，got %v actual=%s", r.Status, r.Actual)
	}
	if r.Actual != "" {
		t.Fatal("平台不符不应计算哈希")
	}
}

func TestCheckEntryAnyPlatformStillHashes(t *testing.T) {
	dataDir := t.TempDir()
	content := []byte("bin")
	sum := sha256.Sum256(content)
	p := filepath.Join(dataDir, "tools", "httpx")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, content, 0o700); err != nil {
		t.Fatal(err)
	}
	ok := CheckEntry(Entry{
		Name: "httpx", Path: "tools/httpx", Platform: "any",
		SHA256: hex.EncodeToString(sum[:]),
	}, dataDir)
	if ok.Status != StatusOK {
		t.Fatalf("any 应继续校验哈希, got %v", ok.Status)
	}
	bad := CheckEntry(Entry{
		Name: "httpx", Path: "tools/httpx", Platform: runtime.GOOS + "/" + runtime.GOARCH,
		SHA256: strings.Repeat("0", 64),
	}, dataDir)
	if bad.Status != StatusMismatch {
		t.Fatalf("当前平台哈希不符应是 mismatch, got %v", bad.Status)
	}
}

func TestDefaultManifestPinsNonOptionalAndOmitsHarvest(t *testing.T) {
	forbidden := []string{
		"mimikatz", "pypykatz", "lazagne", "peass", "impacket", "nxc",
		"suo5-payloads", "penelope",
	}
	pinned := map[string]bool{
		"gogo": true, "naabu": true, "httpx": true, "katana": true, "fscan": true,
	}
	tunnels := map[string]bool{
		"suo5": true, "chisel": true, "ligolo-agent": true, "ligolo-proxy": true,
	}
	hexHash := regexp.MustCompile(`^[0-9a-f]{64}$`)
	m, err := Load(defaultManifestPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Tools) == 0 {
		t.Fatal("默认清单不应为空")
	}
	seenPinned := map[string]bool{}
	seenTunnel := map[string]bool{}
	for _, e := range m.Tools {
		name := strings.ToLower(strings.TrimSpace(e.Name))
		for _, bad := range forbidden {
			if name == bad {
				t.Errorf("默认清单不得包含 %s", e.Name)
			}
		}
		if e.Category != "tunnel" && e.Category != "arsenal" {
			t.Errorf("%s 分类非法: %q", e.Name, e.Category)
		}
		if strings.HasPrefix(name, "ligolo") && e.Category != "tunnel" {
			t.Errorf("%s 若出现只能作为可选隧道检查，got category=%s", e.Name, e.Category)
		}
		if tunnels[name] {
			seenTunnel[name] = true
			if !e.Optional {
				t.Errorf("%s 是隧道类，必须 optional", e.Name)
			}
		}
		if e.Optional {
			if strings.TrimSpace(e.SHA256) != "" {
				t.Errorf("%s 是 optional，sha256 应留空而不是编造, got %q", e.Name, e.SHA256)
			}
			continue
		}
		if pinned[name] {
			seenPinned[name] = true
		}
		if strings.TrimSpace(e.Version) == "" {
			t.Errorf("%s 非 optional 必须有 version", e.Name)
		}
		if !strings.HasPrefix(strings.TrimSpace(e.URL), "https://") {
			t.Errorf("%s 非 optional 必须有 https url, got %q", e.Name, e.URL)
		}
		if !hexHash.MatchString(strings.ToLower(strings.TrimSpace(e.SHA256))) {
			t.Errorf("%s 非 optional 必须有 64 位十六进制 sha256, got %q", e.Name, e.SHA256)
		}
		if strings.TrimSpace(e.Platform) == "" {
			t.Errorf("%s 非 optional 必须有 platform", e.Name)
		}
	}
	for name := range pinned {
		if !seenPinned[name] {
			t.Errorf("侦察工具 %s 应钉版（非 optional，且有 version/url/sha256/platform）", name)
		}
	}
	for name := range tunnels {
		if !seenTunnel[name] {
			t.Errorf("隧道工具 %s 应保留为 optional", name)
		}
	}
}

func TestOptionalManifestIsMetadataOnly(t *testing.T) {
	p := filepath.Join(filepath.Dir(defaultManifestPath(t)), "tools-manifest.optional.json")
	m, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"mimikatz": true, "lazagne": true, "peass": true, "suo5-payloads": true,
	}
	if len(m.Tools) != len(want) {
		t.Fatalf("可选档应只有 %d 条元数据, got %d", len(want), len(m.Tools))
	}
	for _, e := range m.Tools {
		name := strings.ToLower(strings.TrimSpace(e.Name))
		if !want[name] {
			t.Errorf("可选档出现未登记的 %s", e.Name)
		}
		delete(want, name)
		if !e.Optional {
			t.Errorf("%s 必须 optional:true", e.Name)
		}
		if strings.TrimSpace(e.SHA256) != "" {
			t.Errorf("%s 哈希必须留空, got %q", e.Name, e.SHA256)
		}
		if strings.TrimSpace(e.Purpose) == "" {
			t.Errorf("%s 缺少许可/用途备注", e.Name)
		}
	}
	for name := range want {
		t.Errorf("可选档缺少 %s", name)
	}
}
