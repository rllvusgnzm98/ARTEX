package report

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
)

// 中文长标题曾被按字节截断，既可能切在 UTF-8 字符中间，也会把 _#<id> 截掉，
// 导致 zip 条目名非法、多条报告无法按 ID 对应。
func TestFindingFilenameKeepsIDAndValidUTF8(t *testing.T) {
	f := &db.DBFinding{
		ID:       12345,
		Severity: "low",
		Name:     strings.Repeat("中", 80),
	}
	name := FindingFilename(f)

	if !utf8.ValidString(name) {
		t.Fatalf("文件名不是合法 UTF-8: %q", name)
	}
	if !strings.HasSuffix(name, "_#12345.md") {
		t.Fatalf("发现 ID 被截掉: %q", name)
	}
	if len(name) > 120+len(".md") {
		t.Fatalf("文件名超长(%d 字节): %q", len(name), name)
	}
	if strings.ContainsAny(name, `/\`) {
		t.Fatalf("文件名含路径分隔符: %q", name)
	}
}

func TestFindingFilenameShortTitleUnchanged(t *testing.T) {
	f := &db.DBFinding{ID: 7, Severity: "critical", Name: "SQL 注入"}
	got := FindingFilename(f)
	want := "critical_SQL_注入_#7.md"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
