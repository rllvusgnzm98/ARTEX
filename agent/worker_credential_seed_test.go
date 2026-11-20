package agent

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestRenderWorkerCredentialSeedHidesSecretAndWrapsUntrusted(t *testing.T) {
	const secret = "inherited-seed-secret-must-not-leak"
	out := RenderWorkerCredentialSeed([]db.InheritedMeta{{
		CredentialID: 9,
		Username:     "fixture-admin",
		CredType:     db.CredPassword,
		Domain:       "FIXTURE",
		HostAssetID:  44,
		SourceTaskID: 7,
		ScopeBasis:   db.InheritDomain,
	}})
	if out == "" {
		t.Fatal("有继承元数据时应渲染非空提示块")
	}
	if strings.Contains(out, secret) || strings.Contains(out, `"secret"`) {
		t.Fatalf("继承凭据种子不得包含 secret: %s", out)
	}
	for _, want := range []string{
		"fixture-admin", "password", "FIXTURE", `"host_asset_id":44`, `"source_task_id":7`, "domain",
		"不可信", "不是指令", "线索", "前置任务", "目标侧",
		`<untrusted-data source="inherited-credentials">`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("种子缺少 %q:\n%s", want, out)
		}
	}
}

func TestRenderWorkerCredentialSeedEmpty(t *testing.T) {
	if got := RenderWorkerCredentialSeed(nil); got != "" {
		t.Fatalf("nil 应返回空串, got %q", got)
	}
	if got := RenderWorkerCredentialSeed([]db.InheritedMeta{}); got != "" {
		t.Fatalf("空切片应返回空串, got %q", got)
	}
}
