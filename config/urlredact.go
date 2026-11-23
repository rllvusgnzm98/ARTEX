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

// schemePrefix 认出开头的 scheme://；没有它的配置值（代理常写成 u:pw@host:port）按
// 整条都是 authority 处理。
var schemePrefix = regexp.MustCompile(`(?i)^[a-z][a-z0-9+.-]*://`)

// RedactURL 把一条 URL 收敛成「连的是哪个端点」：scheme、主机、端口；userinfo、路径、
// 查询串、片段一律盖掉。
//
// 只保留端点而不保留路径，是几轮评审逼出来的结论：凭据能藏的地方远不止 userinfo 与查询
// 串——参数名可百分号编码，值里可带反引号/尖括号/单引号，口令里可有字面量 @，路径里
// 还能嵌一整条带凭据的 URL（https://gw/proxy/https://u:pw@api/...），也有把令牌直接放进
// 路径段的网关。任何「留下有用部分、只认出凭据」的做法都会漏。完整 base_url 仍由已鉴权
// 的配置页原样回读，日志不需要重复它。
//
// 打码按文本做、不经 net/url：url.Parse+String 会重编码（把 **** 转成 %2A），解析失败的
// URL 也一样要盖。
func RedactURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return raw
	}
	prefix, rest := "", trimmed
	if m := schemePrefix.FindString(rest); m != "" {
		prefix, rest = m, rest[len(m):]
	}
	authority, tail := rest, ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		authority, tail = rest[:i], rest[i:]
	}
	// Go 以第一个 `/` 之前的最后一个 @ 为 userinfo 分隔符；只有用户名的形态也常就是令牌。
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		authority = "****@" + authority[at+1:]
	}
	if i := strings.IndexAny(authority, "?#"); i >= 0 {
		authority = authority[:i+1] + "****"
		tail = ""
	}
	if tail != "" && tail != "/" {
		tail = "/****"
	}
	return prefix + authority + tail
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
