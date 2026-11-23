package config

import (
	"regexp"
	"strings"
)

// 诊断需要的只是「连的是哪个端点」：scheme、主机、端口、路径。凭据恰恰只藏在 userinfo
// 与查询串里，而「哪个参数是凭据、它的值到哪里结束」没法靠枚举判准——参数名可以百分号
// 编码（?%6Bey=），值里可以带反引号、尖括号、单引号这些合法字符。所以查询串整段盖掉，
// 不再逐个认参数名，也不再猜值的字符类。
//
// 打码一律按文本做，不走 net/url：url.Parse+String 会重编码（把 **** 转义成 %2A），
// 而且解析失败的 URL 同样要盖。
//
// URL 在错误文本里的右边界只认空白与双引号：Go 的 url.Error 格式是 `Op "URL": err`。
// 其余标点（反引号、尖括号、单引号、分号）一律算 URL 的一部分，宁可多盖。
var urlInText = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s"]*`)

// userinfoSegment 框出 scheme 与 @ 之间的 userinfo。只有用户名的形态也常就是令牌本身
// （https://TOKEN@host），所以整段盖掉而不是只盖口令。
var schemeUserinfo = regexp.MustCompile(`(?i)^([a-z][a-z0-9+.-]*://)[^/\s]*@`)

// bareUserinfo 处理没有 scheme 的配置值(代理常被写成 u:pw@host:port)。两者都贪婪匹配
// 到第一个 `/` 之前的最后一个 `@`:Go 以最后一个 @ 为 userinfo 分隔符,口令里允许含
// 字面量 @,只盖到第一个 @ 会把后半截口令留在日志里。
var bareUserinfo = regexp.MustCompile(`^[^/\s]*@`)

// RedactURL 打码一条 URL 里的凭据：userinfo 整段与整条查询串，保留 scheme、主机、
// 端口与路径。
func RedactURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return raw
	}
	masked := trimmed
	if i := strings.IndexByte(masked, '?'); i >= 0 {
		masked = masked[:i] + "?****"
	}
	if schemeUserinfo.MatchString(masked) {
		return schemeUserinfo.ReplaceAllString(masked, "${1}****@")
	}
	if !strings.Contains(masked, "://") {
		return bareUserinfo.ReplaceAllString(masked, "****@")
	}
	return masked
}

// ScrubURLValue 把文本里出现的 raw 原样换成它的打码形态。
//
// 用于第三方错误把配置值整条嵌进 message 的情形:RedactURLsInText 只认 scheme:// 开头
// 的 URL,而配置里的代理地址可以没有 scheme(127.0.0.1:7890?token=...),文本扫描认不出
// 它。此处按值替换,不依赖任何形态判断。
func ScrubURLValue(text, raw string) string {
	raw = strings.TrimSpace(raw)
	if text == "" || raw == "" {
		return text
	}
	masked := RedactURL(raw)
	if masked == raw {
		return text
	}
	return strings.ReplaceAll(text, raw, masked)
}

// RedactURLsInText 把文本里出现的每条 URL 都按 RedactURL 打码，其余内容原样保留。
// 用于要落库或进日志的第三方错误信息：它们常把请求 URL 连同凭据一起嵌在 message 里。
func RedactURLsInText(s string) string {
	if s == "" {
		return s
	}
	return urlInText.ReplaceAllStringFunc(s, RedactURL)
}
