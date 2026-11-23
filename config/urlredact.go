package config

import (
	"net/url"
	"regexp"
	"strings"
)

// 凭据既会藏在 URL 的 userinfo 里，也常被网关要求塞进查询串（Google AI 的 ?key=、
// 各家的 ?access_token= 等）。打码两处都要管。
// 凭据既会藏在 URL 的 userinfo 里，也常被网关要求塞进查询串（Google AI 的 ?key=、
// 各家的 ?access_token= 等）。打码两处都要管。
//
// 查询串一律按**文本**打码，不走 url.Query()：那条路要求整条 URL 解析成功，而且
// Go 的 ParseQuery 会把含分号的键值对静默丢掉，于是「解析失败」和「分号分隔」两种
// 形态都会原样漏出去。值的字符类特意包含单引号——URL 在错误文本里被单引号截断时，
// 按 URL 逐条打码会把引号后的半截凭据留下。
var queryCredential = regexp.MustCompile(`(?i)([?&;](?:key|api[-_]?key|access[-_]?token|token|auth|authorization|password|passwd|pwd|secret|sig|signature|sslpassword)=)[^&;#\s"` + "`" + `<>]*`)

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
	masked := queryCredential.ReplaceAllString(raw, "${1}****")
	u, err := url.Parse(strings.TrimSpace(masked))
	if err != nil || u.Scheme == "" {
		// 解析失败时至少把 scheme 与 @ 之间的 userinfo 抹掉；查询串已在上面按文本打过码。
		return userinfoInText.ReplaceAllString(masked, "${1}****@")
	}
	if u.User == nil {
		return masked
	}
	// 只有用户名的 userinfo 也常就是令牌本身（https://TOKEN@host），整段盖掉。
	if _, hasPw := u.User.Password(); hasPw {
		u.User = url.UserPassword(u.User.Username(), "****")
	} else if u.User.Username() != "" {
		u.User = url.User("****")
	}
	return u.String()
}

// RedactURLsInText 把文本里出现的每条 URL 都按 RedactURL 打码，其余内容原样保留。
// 用于要落库或进日志的第三方错误信息：它们常把请求 URL 连同凭据一起嵌在 message 里。
func RedactURLsInText(s string) string {
	if s == "" {
		return s
	}
	// 查询串凭据先按整段文本打码：URL 的边界（引号、单引号）判断不可靠，漏框一个字符
	// 就会留下半截凭据。
	s = queryCredential.ReplaceAllString(s, "${1}****")
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
