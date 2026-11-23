package config

import (
	"strings"
	"testing"
)

// RedactURL 只留「连的是哪个端点」：scheme + 主机 + 端口。
func TestRedactURLKeepsOnlyEndpoint(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"userinfo password", "http://user:SECRETPW@proxy.local:8080", "http://****@proxy.local:8080"},
		{"socks5", "socks5://user:SECRETPW@10.0.0.1:1080", "socks5://****@10.0.0.1:1080"},
		{"username as token", "https://SECRETTOKEN@api.example.com/v1", "https://****@api.example.com/****"},
		{"query credential", "https://api.example.com/v1?key=SECRETKEY&alt=sse", "https://api.example.com/****"},
		{"percent-encoded name", "https://api.example.com/v1?%6Bey=SECRETKEY", "https://api.example.com/****"},
		{"backtick in value", "https://api.example.com/v1?key=SEC`RETKEY", "https://api.example.com/****"},
		{"angle in value", "https://api.example.com/v1?key=SEC<RETKEY", "https://api.example.com/****"},
		{"apostrophe in value", "https://api.example.com/v1?key=SEC'RETKEY", "https://api.example.com/****"},
		{"semicolon separated", "https://api.example.com/v1?key=SECRETKEY;alt=sse", "https://api.example.com/****"},
		{"query on authority", "https://api.example.com?key=SECRETKEY", "https://api.example.com?****"},
		{"fragment", "https://api.example.com#SECRETFRAG", "https://api.example.com#****"},
		{"unparseable port", "http://h:notaport/v1?key=SECRETKEY", "http://h:notaport/****"},
		{"at inside password", "https://user:SEC@RETPW@api.example.com/v1", "https://****@api.example.com/****"},
		{"nested url in path", "https://gw.example.com/proxy/https://user:SECRETPW@api.example.com/v1", "https://gw.example.com/****"},
		{"token in path segment", "https://api.example.com/v1/SECRETTOKEN/chat", "https://api.example.com/****"},
		{"no scheme with userinfo", "u:SEC@RETPW@127.0.0.1:7890", "****@127.0.0.1:7890"},
		{"no scheme with query", "127.0.0.1:7890?token=SECRETTOK", "127.0.0.1:7890?****"},
		{"at inside query", "https://api.example.com?redirect=a@b&key=SECRETKEY", "https://****?****"},
		{"raw ? inside password", "https://u:SEC?RET@api.example.com/v1", "https://****?****"},
		{"userinfo then query", "https://TOKEN@api.example.com?key=SECRETKEY", "https://****@api.example.com?****"},
		{"at inside fragment", "https://api.example.com#a@b&SECRETFRAG", "https://****#****"},
		{"plain endpoint", "https://api.openai.com", "https://api.openai.com"},
		{"plain host port", "127.0.0.1:7890", "127.0.0.1:7890"},
		{"trailing slash", "https://api.openai.com/", "https://api.openai.com/"},
		{"empty", "", ""},
	}
	for _, c := range cases {
		got := RedactURL(c.in)
		if got != c.want {
			t.Errorf("%s: RedactURL(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
		for _, leak := range []string{"SECRET", "RETPW", "RETKEY", "TOKEN", "FRAG"} {
			if strings.Contains(got, leak) {
				t.Errorf("%s: RedactURL(%q) = %q, leaks %q", c.name, c.in, got, leak)
			}
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
		`Post "https://gw.example.com/proxy/https://u:SECRETPW@api.example.com/v1": dial tcp: connection refused`,
		`parse "socks5://u:SECRETPW@h:bad": invalid port ":bad" after host`,
	}
	for _, in := range cases {
		got := RedactURLsInText(in)
		for _, leak := range []string{"SECRET", "RETKEY", "RETPW"} {
			if strings.Contains(got, leak) {
				t.Errorf("RedactURLsInText(%q) = %q, leaks %q", in, got, leak)
			}
		}
		if !strings.Contains(got, "connection refused") && !strings.Contains(got, "invalid port") {
			t.Errorf("RedactURLsInText lost diagnostic context: %q", got)
		}
		if !strings.Contains(got, "127.0.0.1:1") && !strings.Contains(got, "example.com") && !strings.Contains(got, "h:bad") {
			t.Errorf("RedactURLsInText lost the endpoint: %q", got)
		}
	}
	plain := "context deadline exceeded"
	if got := RedactURLsInText(plain); got != plain {
		t.Errorf("RedactURLsInText changed URL-free text: %q", got)
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
