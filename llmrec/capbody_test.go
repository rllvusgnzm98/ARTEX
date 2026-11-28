package llmrec

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// 落库截断回归：大正文必须截到上限内、保留完整 rune（截断点不劈开多字节字符）、
// 且带原始大小标记；小正文原样通过。
func TestCapBodyTruncatesAtRuneBoundary(t *testing.T) {
	// 短正文原样返回。
	short := "hello"
	if got := capBody(short); got != short {
		t.Errorf("short body mutated: %q", got)
	}
	if got := capBody(""); got != "" {
		t.Errorf("empty body mutated: %q", got)
	}
	// 恰好上限不截断。
	exact := strings.Repeat("a", maxBodyBytes)
	if got := capBody(exact); got != exact {
		t.Errorf("exactly-at-limit body mutated (len %d)", len(got))
	}

	// 超限：ASCII 截断 + 标记。
	big := strings.Repeat("x", maxBodyBytes+500)
	got := capBody(big)
	if len(got) >= len(big) {
		t.Errorf("big body not truncated: len %d", len(got))
	}
	if !strings.Contains(got, "已截断") {
		t.Error("truncation marker missing")
	}
	if !strings.Contains(got, "上限") {
		t.Error("size annotation missing")
	}

	// 多字节 rune：截断点绝不劈开字符（否则落库是损坏 UTF-8，影响 UI/检索）。
	// 构造一个上限边界处正好落在「中」字中间的正文：填充到 maxBodyBytes-2，
	// 再放一个 3 字节的「中」，使 maxBodyBytes 落在该字第 2 字节上。
	pad := strings.Repeat("a", maxBodyBytes-2)
	multibyte := pad + "中文中文中文" + strings.Repeat("z", 5000)
	got = capBody(multibyte)
	if !utf8.ValidString(got) {
		t.Error("truncated body is not valid UTF-8 — rune boundary split")
	}
	// 截断前缀部分也必须合法。
	prefixEnd := strings.Index(got, "\n…")
	if prefixEnd <= 0 {
		t.Fatal("marker boundary not found")
	}
	if !utf8.ValidString(got[:prefixEnd]) {
		t.Error("prefix before marker is invalid UTF-8")
	}
	if len(got[:prefixEnd]) > maxBodyBytes {
		t.Errorf("prefix len %d exceeds cap %d", len(got[:prefixEnd]), maxBodyBytes)
	}
}
