package server

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestHackbotsScriptSmoke 在本机解释器上跑随包脚本的无网络路径：本地抽端点、
// 只打印指纹计划、dry-run 列 chunk、Caido CLI 缺失时失败且不编造流量。
// 技能目录和工具注册分属两次提交，脚本还没合进来时跳过。
func TestHackbotsScriptSmoke(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "skills"))
	if err != nil {
		t.Fatal(err)
	}
	extract := filepath.Join(root, "js-api-recon", "scripts", "regex", "extract_endpoints.py")
	if _, err := os.Stat(extract); err != nil {
		t.Skip("本树没有 Hackbots 脚本，跳过冒烟")
	}
	py := detectPython()
	if py == "" {
		t.Skip("未检测到 python")
	}

	dir := t.TempDir()
	js := filepath.Join(dir, "app.js")
	body := "fetch(\"/api/v1/users\");\nconst chunk = \"static/js/vendor.chunk.js\";\n"
	if err := os.WriteFile(js, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	out := runSmoke(t, dir, py, extract, js)
	if !strings.Contains(out, "/api/v1/users") {
		t.Fatalf("extract_endpoints 未抽出端点:\n%s", out)
	}

	plan := filepath.Join(root, "js-api-recon", "scripts", "caido", "plan_http_fingerprint_probes.py")
	out = runSmoke(t, dir, py, plan, "https://example.com")
	if !strings.Contains(out, "requires_user_authorization") || !strings.Contains(out, "banner-grabbing") {
		t.Fatalf("指纹计划不像预期:\n%s", out)
	}

	missing := filepath.Join(dir, "no-such-caido-cli")
	caido := filepath.Join(root, "js-api-recon", "scripts", "caido", "collect_caido_api_traffic.py")
	out, err = runSmokeRaw(dir, py, caido, "example.com", "--caido-cli", missing)
	if err == nil {
		t.Fatalf("Caido CLI 缺失时应失败，输出:\n%s", out)
	}
	if !strings.Contains(out, "caido CLI not found") {
		t.Fatalf("Caido 缺失时的错误不可读:\n%s", out)
	}

	node := detectNode()
	if node == "" {
		t.Log("未检测到 node，跳过 lazy chunk dry-run")
		return
	}
	script := filepath.Join(root, "js-api-recon", "scripts", "chunks", "fetch_lazy_chunks.js")
	out = runSmoke(t, dir, node, script, "https://example.com/", "--dir", dir, "--dry-run")
	if !strings.Contains(out, "static/js/vendor.chunk.js") {
		t.Fatalf("dry-run 未列出 chunk:\n%s", out)
	}
}

func runSmoke(t *testing.T, dir, bin string, args ...string) string {
	t.Helper()
	out, err := runSmokeRaw(dir, bin, args...)
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", bin, args, err, out)
	}
	return out
}

func runSmokeRaw(dir, bin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}
