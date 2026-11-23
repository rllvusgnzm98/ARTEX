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
var userinfoSegment = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/\s@]*@`)

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
	return userinfoSegment.ReplaceAllString(masked, "${1}****@")
}

// RedactURLsInText 把文本里出现的每条 URL 都按 RedactURL 打码，其余内容原样保留。
// 用于要落库或进日志的第三方错误信息：它们常把请求 URL 连同凭据一起嵌在 message 里。
func RedactURLsInText(s string) string {
	if s == "" {
		return s
	}
	return urlInText.ReplaceAllStringFunc(s, RedactURL)
}
