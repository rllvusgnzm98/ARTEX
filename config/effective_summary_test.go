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
	// DSN 串本身已不再落库（见 TestEffectiveSummaryKeepsNoDSN）；这里只校验「连的是
	// 哪台库」仍能从身份白名单里看出来。
	if host, _ := sum["db_host"].(string); host != "db.internal" {
		t.Fatalf("仍该看得出连的是哪台库，实际 %q", host)
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

// TestScrubSecretsCoversPgxDiagnostics 覆盖评审第 1 条确认的泄漏：pgx 的解析错误会把
// 整条 DSN 嵌进 message，而它只打码 URL userinfo 与 libpq 键值，查询串里的 password /
// sslpassword 一概留原文。按值抹除必须把这些形态都盖住。
func TestScrubSecretsCoversPgxDiagnostics(t *testing.T) {
	cases := []struct{ name, dsn, secret string }{
		{"查询串口令", "postgres://artex@h:5432/artex?password=QS-PW&sslmode=bogus", "QS-PW"},
		{"sslpassword", "postgres://artex@h:5432/artex?sslpassword=SSL-PW&sslmode=bogus", "SSL-PW"},
		{"userinfo", "postgres://artex:UI-PW@h:5432/artex?sslmode=bogus", "UI-PW"},
		{"键值带空格", "host=h user=artex password = KV-PW sslmode=bogus", "KV-PW"},
		{"键值引号转义", `host=h user=artex password='KV\'QPW' sslmode=bogus`, `KV\'QPW`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// 模拟 pgx 的原文诊断（实测形如 cannot parse `<整条 DSN>`: ...）。
			diag := "cannot parse `" + c.dsn + "`: failed to configure TLS (sslmode is invalid)"
			got := ScrubSecrets(c.dsn, diag)
			if strings.Contains(got, c.secret) {
				t.Fatalf("诊断文本里仍有口令原文:\n  %s", got)
			}
			if !strings.Contains(got, "sslmode is invalid") {
				t.Fatalf("诊断信息本身不该被抹掉: %s", got)
			}
		})
	}
}

// TestEffectiveSummaryKeepsNoDSN 确认落库的是连接身份白名单，而不是一条（几乎完整的）DSN。
func TestEffectiveSummaryKeepsNoDSN(t *testing.T) {
	t.Setenv("ARTEX_PG_DSN", "postgres://artex:PW-NOPE@db.internal:5432/artexdb?sslmode=require")
	sum := EffectiveSummary()

	if _, ok := sum["db_dsn_redacted"]; ok {
		t.Fatal("不该再落 DSN 串（打码与否都不该）")
	}
	for k, v := range sum {
		if s, ok := v.(string); ok && strings.Contains(s, "PW-NOPE") {
			t.Fatalf("键 %q 泄露了口令", k)
		}
	}
	for _, want := range []struct{ k, v string }{
		{"db_host", "db.internal"}, {"db_name", "artexdb"}, {"db_user", "artex"},
	} {
		if got, _ := sum[want.k].(string); got != want.v {
			t.Fatalf("身份字段 %s 该是 %q，实际 %q", want.k, want.v, got)
		}
	}
	if port, _ := sum["db_port"].(uint16); port != 5432 {
		t.Fatalf("db_port 该是 5432，实际 %v", sum["db_port"])
	}
	if tls, _ := sum["db_tls_enabled"].(bool); !tls {
		t.Fatal("sslmode=require 该记成启用了 TLS")
	}
	if set, _ := sum["db_password_set"].(bool); !set {
		t.Fatal("该如实记下「配了口令」这一事实")
	}
}

// TestConnectionIdentityUsesRealParser 覆盖手写切分会错的三种 DSN：引号里的口令可以含
// 空格甚至 "dbname=" 字样、`=` 两侧可以有空白、URL 查询串能覆盖 host/port/dbname。
// 这些都曾让快照指向错误的库，或把口令碎片当成库名记进去。
func TestConnectionIdentityUsesRealParser(t *testing.T) {
	t.Run("引号口令不得被当成库名", func(t *testing.T) {
		id := connectionIdentity(`host=h user=u password='pw dbname=LEAKED'`)
		if name, _ := id["db_name"].(string); strings.Contains(name, "LEAKED") {
			t.Fatalf("口令碎片被当成了库名: %v", id)
		}
		for k, v := range id {
			if sv, ok := v.(string); ok && strings.Contains(sv, "LEAKED") {
				t.Fatalf("键 %q 带出了口令碎片: %v", k, sv)
			}
		}
		if set, _ := id["db_password_set"].(bool); !set {
			t.Fatalf("该认出配了口令: %v", id)
		}
	})

	t.Run("等号两侧空白仍要有身份", func(t *testing.T) {
		id := connectionIdentity("host = h user = u dbname = spaced")
		if host, _ := id["db_host"].(string); host != "h" {
			t.Fatalf("host 没解析出来: %v", id)
		}
		if name, _ := id["db_name"].(string); name != "spaced" {
			t.Fatalf("dbname 没解析出来: %v", id)
		}
	})

	t.Run("URL查询串覆盖要生效", func(t *testing.T) {
		id := connectionIdentity("postgres://u:pw@h:5432/urldb?host=other&port=6543&dbname=overridden&sslmode=disable")
		if host, _ := id["db_host"].(string); host != "other" {
			t.Fatalf("查询串里的 host 覆盖没生效: %v", id)
		}
		if port, _ := id["db_port"].(uint16); port != 6543 {
			t.Fatalf("查询串里的 port 覆盖没生效: %v", id)
		}
		if name, _ := id["db_name"].(string); name != "overridden" {
			t.Fatalf("查询串里的 dbname 覆盖没生效: %v", id)
		}
	})

	t.Run("解析失败时不猜身份", func(t *testing.T) {
		id := connectionIdentity("postgres://u@h:5432/db?password=QS-PW&sslmode=bogus-tls-mode")
		if parsed, _ := id["db_identity_parsed"].(bool); parsed {
			t.Fatalf("sslmode 非法时不该自称解析成功: %v", id)
		}
		if _, ok := id["db_host"]; ok {
			t.Fatalf("解析失败就不该给出身份字段: %v", id)
		}
		for k, v := range id {
			if sv, ok := v.(string); ok && strings.Contains(sv, "QS-PW") {
				t.Fatalf("键 %q 泄露了口令: %v", k, sv)
			}
		}
	})
}
