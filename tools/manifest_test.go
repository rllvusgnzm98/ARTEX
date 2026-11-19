package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
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

func TestDefaultManifestOmitsHarvestAndLeavesHashesEmpty(t *testing.T) {
	forbidden := []string{
		"mimikatz", "pypykatz", "lazagne", "peass", "impacket", "nxc",
		"suo5-payloads", "penelope",
	}
	m, err := Load(defaultManifestPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Tools) == 0 {
		t.Fatal("默认清单不应为空")
	}
	for _, e := range m.Tools {
		name := strings.ToLower(strings.TrimSpace(e.Name))
		for _, bad := range forbidden {
			if name == bad {
				t.Errorf("默认清单不得包含 %s", e.Name)
			}
		}
		if strings.TrimSpace(e.SHA256) != "" {
			t.Errorf("%s 的 sha256 应留空（不要抄现场哈希），got %q", e.Name, e.SHA256)
		}
		if e.Category != "tunnel" && e.Category != "arsenal" {
			t.Errorf("%s 分类非法: %q", e.Name, e.Category)
		}
		if strings.HasPrefix(name, "ligolo") && e.Category != "tunnel" {
			t.Errorf("%s 若出现只能作为可选随道检查，got category=%s", e.Name, e.Category)
		}
	}
}
