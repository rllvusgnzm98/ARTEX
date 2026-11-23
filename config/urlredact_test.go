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
		{"https://generativelanguage.googleapis.com/v1beta?key=SECRETKEY&alt=sse", "alt=sse"},
		{"https://api.example.com/v1?access_token=SECRETTOK", "api.example.com/v1"},
		{"http://u:SECRET%40PW@h:1", "h:1"},
	}
	for _, c := range cases {
		got := RedactURL(c.in)
		for _, leak := range []string{"SECRET"} {
			if strings.Contains(got, leak) {
				t.Errorf("RedactURL(%q) = %q, still contains secret", c.in, got)
			}
		}
		if !strings.Contains(got, c.mustKeep) {
			t.Errorf("RedactURL(%q) = %q, lost endpoint %q", c.in, got, c.mustKeep)
		}
	}
}

func TestRedactURLKeepsCredentialFreeURL(t *testing.T) {
	for _, in := range []string{"", "https://api.openai.com/v1", "http://127.0.0.1:7890", "https://h/v1?model=x"} {
		if got := RedactURL(in); got != in {
			t.Errorf("RedactURL(%q) = %q, want unchanged", in, got)
		}
	}
}

func TestRedactURLMalformedFallsBackToStrippingUserinfo(t *testing.T) {
	got := RedactURL("http://user:SECRET@h:notaport")
	if strings.Contains(got, "SECRET") {
		t.Fatalf("malformed URL leaked: %q", got)
	}
}

func TestRedactURLsInTextScrubsEmbeddedURLs(t *testing.T) {
	cases := []string{
		// 实测 net/http 的错误：口令被盖成 ***，但查询串 key 与纯令牌用户名原样保留。
		`Get "http://127.0.0.1:1/v1/models?key=SECRETKEY": dial tcp 127.0.0.1:1: connect: connection refused`,
		`Post "http://SECRETTOKEN@127.0.0.1:1/v1/chat": dial tcp 127.0.0.1:1: connect: connection refused`,
		// url.Parse 的报错会把原串整个引出来。
		`parse "socks5://u:SECRETPW@h:bad": invalid port ":bad" after host`,
	}
	for _, in := range cases {
		got := RedactURLsInText(in)
		if strings.Contains(got, "SECRET") {
			t.Errorf("RedactURLsInText leaked: %q", got)
		}
		if !strings.Contains(got, "127.0.0.1:1") && !strings.Contains(got, "invalid port") {
			t.Errorf("RedactURLsInText lost diagnostic context: %q", got)
		}
	}
	plain := "context deadline exceeded"
	if got := RedactURLsInText(plain); got != plain {
		t.Errorf("RedactURLsInText changed URL-free text: %q", got)
	}
}
