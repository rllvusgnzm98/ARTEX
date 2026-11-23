package config

import (
	"strings"
	"testing"
)

func TestRedactURLMasksCredentials(t *testing.T) {
	cases := []struct{ in, mustKeep string }{
		{"http://user:SECRETPW@proxy.local:8080", "proxy.local:8080"},
		{"socks5://user:SECRETPW@10.0.0.1:1080", "10.0.0.1:1080"},
		{"https://SECRETTOKEN@api.example.com/v1", "api.example.com/v1"},
		{"https://generativelanguage.googleapis.com/v1beta?key=SECRETKEY&alt=sse", "googleapis.com/v1beta"},
		{"https://api.example.com/v1?access_token=SECRETTOK", "api.example.com/v1"},
		{"http://u:SECRET%40PW@h:1", "h:1"},
	}
	for _, c := range cases {
		got := RedactURL(c.in)
		if strings.Contains(got, "SECRET") {
			t.Errorf("RedactURL(%q) = %q, still contains secret", c.in, got)
		}
		if !strings.Contains(got, c.mustKeep) {
			t.Errorf("RedactURL(%q) = %q, lost endpoint %q", c.in, got, c.mustKeep)
		}
	}
}

func TestRedactURLKeepsCredentialFreeEndpoint(t *testing.T) {
	// 没有查询串也没有 userinfo 的 URL 一字不改：端点本身就是诊断要看的东西。
	for _, in := range []string{"", "https://api.openai.com/v1", "http://127.0.0.1:7890", "socks5://10.0.0.1:1080"} {
		if got := RedactURL(in); got != in {
			t.Errorf("RedactURL(%q) = %q, want unchanged", in, got)
		}
	}
}

// 查询串整段盖掉，不逐个认参数名：参数名可百分号编码，值里可带合法的反引号/尖括号/
// 单引号，任何「认名字 + 猜值边界」的做法都会漏（Devin Review 两轮各查到一批）。
func TestRedactURLMasksWholeQueryString(t *testing.T) {
	cases := []struct{ name, in, mustKeep string }{
		{"plain credential", "https://api.example.com/v1?key=SECRETKEY", "api.example.com/v1"},
		{"percent-encoded name", "https://api.example.com/v1?%6Bey=SECRETKEY", "api.example.com/v1"},
		{"backtick in value", "https://api.example.com/v1?key=SEC`RETKEY", "api.example.com/v1"},
		{"angle bracket in value", "https://api.example.com/v1?key=SEC<RETKEY", "api.example.com/v1"},
		{"apostrophe in value", "https://api.example.com/v1?key=SEC'RETKEY", "api.example.com/v1"},
		{"semicolon separated", "https://api.example.com/v1?key=SECRETKEY;alt=sse", "api.example.com/v1"},
		{"unparseable port", "http://h:notaport/v1?key=SECRETKEY", "/v1"},
		{"userinfo and query", "https://TOKEN@api.example.com/v1?key=SECRETKEY", "api.example.com/v1"},
	}
	for _, c := range cases {
		got := RedactURL(c.in)
		for _, leak := range []string{"SECRET", "RETKEY", "TOKEN"} {
			if strings.Contains(got, leak) {
				t.Errorf("%s: RedactURL(%q) = %q, leaks %q", c.name, c.in, got, leak)
			}
		}
		if !strings.Contains(got, c.mustKeep) {
			t.Errorf("%s: RedactURL(%q) = %q, lost endpoint", c.name, c.in, got)
		}
		if strings.Contains(got, "%2A") {
			t.Errorf("%s: RedactURL(%q) = %q, re-encoded the mask", c.name, c.in, got)
		}
	}
}

func TestRedactURLsInTextScrubsEmbeddedURLs(t *testing.T) {
	// 实测的 net/http 错误：口令被盖成 ***，但查询串 key 与「用户名即令牌」原样保留。
	cases := []string{
		`Get "http://127.0.0.1:1/v1/models?key=SECRETKEY": dial tcp 127.0.0.1:1: connect: connection refused`,
		`Post "http://SECRETTOKEN@127.0.0.1:1/v1/chat": dial tcp 127.0.0.1:1: connect: connection refused`,
		`Post "https://api.example.com/v1?key=SEC` + "`" + `RETKEY": dial tcp: connection refused`,
		`parse "socks5://u:SECRETPW@h:bad": invalid port ":bad" after host`,
	}
	for _, in := range cases {
		got := RedactURLsInText(in)
		for _, leak := range []string{"SECRET", "RETKEY"} {
			if strings.Contains(got, leak) {
				t.Errorf("RedactURLsInText(%q) = %q, leaks %q", in, got, leak)
			}
		}
		if !strings.Contains(got, "connection refused") && !strings.Contains(got, "invalid port") {
			t.Errorf("RedactURLsInText lost diagnostic context: %q", got)
		}
	}
	plain := "context deadline exceeded"
	if got := RedactURLsInText(plain); got != plain {
		t.Errorf("RedactURLsInText changed URL-free text: %q", got)
	}
}

// Go 以最后一个 @ 为 userinfo 分隔符,口令里允许字面量 @;代理地址也常不带 scheme。
func TestRedactURLUserinfoEdgeForms(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"at in password", "https://user:SEC@RETPW@api.example.com/v1", "https://****@api.example.com/v1"},
		{"at in password no scheme", "u:SEC@RETPW@127.0.0.1:7890", "****@127.0.0.1:7890"},
		{"scheme-less query", "127.0.0.1:7890?token=SECRETTOK", "127.0.0.1:7890?****"},
		{"scheme-less plain", "127.0.0.1:7890", "127.0.0.1:7890"},
		{"at only in path", "https://api.example.com/v1/a@b", "https://api.example.com/v1/a@b"},
	}
	for _, c := range cases {
		if got := RedactURL(c.in); got != c.want {
			t.Errorf("%s: RedactURL(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestScrubURLValueCatchesSchemelessConfig(t *testing.T) {
	raw := "u:SECRETPW@127.0.0.1:7890?token=SECRETTOK"
	msg := `llm: invalid proxy "` + raw + `": parse "` + raw + `": first path segment in URL cannot contain colon`
	got := ScrubURLValue(msg, raw)
	if strings.Contains(got, "SECRET") {
		t.Fatalf("ScrubURLValue leaked: %q", got)
	}
	if !strings.Contains(got, "127.0.0.1:7890") || !strings.Contains(got, "cannot contain colon") {
		t.Fatalf("ScrubURLValue lost context: %q", got)
	}
	if got := ScrubURLValue("no proxy here", raw); got != "no proxy here" {
		t.Fatalf("ScrubURLValue changed unrelated text: %q", got)
	}
}
