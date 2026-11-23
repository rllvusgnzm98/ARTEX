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

// TestRedactMasksQueryStringPassword 覆盖 URL 查询串里的口令：keywordSecret 要求键前是
// 行首或空白，`?password=` / `&password=` 都不匹配，所以只靠它会把口令原样留在脱敏串里，
// 再经运行溯源落库、从 task stats 读出去。
func TestRedactMasksQueryStringPassword(t *testing.T) {
	const secret = "pw-in-query"
	for _, dsn := range []string{
		"postgres://artex@h:5432/artex?password=" + secret + "&sslmode=disable",
		"postgres://artex@h:5432/artex?sslmode=disable&PassWord=" + secret,
		"postgres://artex@h:5432/artex?passfile=/x&pwd=" + secret,
	} {
		got := Redact(dsn)
		if strings.Contains(got, secret) {
			t.Fatalf("查询串里的口令没打码:\n  输入: %s\n  输出: %s", dsn, got)
		}
		if !strings.Contains(got, "h:5432") {
			t.Fatalf("脱敏后仍该看得出连的是哪台库: %s", got)
		}
	}

	// 非口令参数不受影响。
	if got := Redact("postgres://artex@h:5432/artex?sslmode=require"); !strings.Contains(got, "sslmode=require") {
		t.Fatalf("普通参数被改动了: %s", got)
	}
}

// TestEffectiveSummaryOmitsHostPace 确认 config 侧不再自称知道每主机限速的生效值：
// 它可由 Settings 在运行期改写，只有 Manager 知道，server 侧负责补上。
func TestEffectiveSummaryOmitsHostPace(t *testing.T) {
	if _, ok := EffectiveSummary()["host_pace_rps"]; ok {
		t.Fatal("config 摘要不该带 host_pace_rps（那只会是启动默认值）")
	}
}
