package config

import (
	"strings"
	"testing"
)

// TestEffectiveSummaryUsesEffectiveValuesAndRedacts 确认运行溯源拿到的是「进程实际在用
// 的取值」而不是配置文件内容：环境变量里的 DSN 必须体现在来源里，且口令绝不落原文。
func TestEffectiveSummaryUsesEffectiveValuesAndRedacts(t *testing.T) {
	const secret = "sup3rs3cr3t-pw"
	t.Setenv("ARTEX_PG_DSN", "postgres://artex:"+secret+"@db.internal:5432/artex?sslmode=disable")

	sum := EffectiveSummary()

	if set, _ := sum["db_dsn_set"].(bool); !set {
		t.Fatalf("环境变量里的 DSN 该被认出来: %+v", sum)
	}
	if src, _ := sum["db_dsn_source"].(string); !strings.Contains(src, "ARTEX_PG_DSN") {
		t.Fatalf("该如实记下生效来源，实际 %q", src)
	}
	red, _ := sum["db_dsn_redacted"].(string)
	if strings.Contains(red, secret) {
		t.Fatal("脱敏 DSN 里出现了口令原文")
	}
	if !strings.Contains(red, "db.internal") {
		t.Fatalf("脱敏后仍该看得出连的是哪台库，实际 %q", red)
	}

	// 整个摘要里不得出现口令原文（任何键）。
	for k, v := range sum {
		if s, ok := v.(string); ok && strings.Contains(s, secret) {
			t.Fatalf("键 %q 泄露了口令原文", k)
		}
	}
}
