package config

import (
	"net/url"
	"regexp"
	"strings"
)

// 凭据既会藏在 URL 的 userinfo 里，也常被网关要求塞进查询串（Google AI 的 ?key=、
// 各家的 ?access_token= 等）。打码两处都要管。
var urlSecretQueryKeys = map[string]struct{}{
	"key": {}, "api_key": {}, "apikey": {}, "api-key": {},
	"access_token": {}, "token": {}, "auth": {}, "authorization": {},
	"password": {}, "passwd": {}, "pwd": {}, "secret": {},
	"sig": {}, "signature": {}, "sslpassword": {},
}

// urlInText 粗略框出文本里的 URL。第三方错误信息常把请求 URL 原样嵌进 message
// （net/url.Error 就是这么拼的），所以要能在任意文本里找到它们再打码。
var urlInText = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s"'` + "`" + `<>\\]+`)

// userinfoInText 兜底：URL 解析失败时，至少把 scheme 与 @ 之间的 userinfo 抹掉。
var userinfoInText = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/\s@]*@`)

// RedactURL 打码一条 URL 里的凭据：userinfo 口令与常见的凭据查询参数。
//
// 保留用户名、主机、路径与其它参数——日志和诊断的价值就在于看得出「连的是哪个端点」，
// 只需要让凭据本身不可读。解析失败时退回到抹掉 userinfo 整段，宁可多盖。
func RedactURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return raw
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Scheme == "" {
		return userinfoInText.ReplaceAllString(raw, "${1}****@")
	}
	if u.User != nil {
		// 只有用户名的 userinfo 也常就是令牌本身（https://TOKEN@host），整段盖掉。
		if _, hasPw := u.User.Password(); hasPw {
			u.User = url.UserPassword(u.User.Username(), "****")
		} else if u.User.Username() != "" {
			u.User = url.User("****")
		}
	}
	if q := u.Query(); len(q) > 0 {
		masked := false
		for k, vs := range q {
			if _, secret := urlSecretQueryKeys[strings.ToLower(k)]; !secret {
				continue
			}
			for i := range vs {
				if vs[i] != "" {
					vs[i] = "****"
					masked = true
				}
			}
			q[k] = vs
		}
		if masked {
			u.RawQuery = q.Encode()
		}
	}
	return u.String()
}

// RedactURLsInText 把文本里出现的每条 URL 都按 RedactURL 打码，其余内容原样保留。
// 用于要落库或进日志的第三方错误信息：它们常把请求 URL 连同凭据一起嵌在 message 里。
func RedactURLsInText(s string) string {
	if s == "" {
		return s
	}
	return urlInText.ReplaceAllStringFunc(s, func(raw string) string {
		// URL 常被引号或标点收尾（`Post "https://...": dial tcp`），尾随符号不该进 URL。
		trailing := ""
		for len(raw) > 0 {
			last := raw[len(raw)-1]
			if last == '"' || last == '\'' || last == ':' || last == ',' || last == ';' || last == '.' || last == ')' {
				trailing = string(last) + trailing
				raw = raw[:len(raw)-1]
				continue
			}
			break
		}
		return RedactURL(raw) + trailing
	})
}
