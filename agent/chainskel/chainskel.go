// Package chainskel 承载反问思维链(chains)的 L2/L3 蒸馏产物与路由逻辑
// (CHAINS-INTEGRATION-DESIGN.md §3):
//
//   - L3 场景骨架:按 Categories 分类的
//     "场景→判据→转向"决策骨架,离线人工蒸馏为 <category>.md,go:embed 进二进制,
//     按意图 chain_tags(或回退关键词匹配)注入 worker system —— 代码路由,不靠模型。
//   - L2 meta 铁律:planner/worker 两份常量文本(meta_rules.go),追加在各自
//     system prompt 的代码固定尾(静态,利于缓存)。
//
// 兜底原则:骨架缺失/读取失败、tag 非法、匹配不中,一律静默降级为不注入,
// 绝不阻断 worker 启动。
package chainskel

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed *.md
var skeletonFS embed.FS

// Categories 是合法的 chain_tags 取值。
var Categories = []string{"web", "ad", "app", "priv", "pwn", "recon", "rev", "pivot", "meta", "patch", "firmware", "audit", "identity", "cloud", "protocol"}

// MaxTagsPerIntent 是公开标签校验上限;ForIntent 只注入首个主类别。
const MaxTagsPerIntent = 2

// sectionCapRunes 是注入 worker system 的骨架块总字符(rune)上限,超出截断并标注。
// 包级变量以便测试调小验证截断路径。
var sectionCapRunes = 8000

// Valid 报告 tag 是否是合法的 chain_tags 取值。
func Valid(tag string) bool {
	for _, c := range Categories {
		if tag == c {
			return true
		}
	}
	return false
}

// NormalizeChainTags 规整标签(小写、去空白、去重、保序)。
func NormalizeChainTags(tags []string) []string {
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		dup := false
		for _, o := range out {
			if o == t {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, t)
		}
	}
	return out
}

// ValidateChainTags 校验标签:取值必须 ∈ Categories,且至多 MaxTagsPerIntent 个
// (兼容已有双标签 payload;主骨架只取首个合法标签)。
func ValidateChainTags(tags []string) error {
	for _, t := range tags {
		if !Valid(t) {
			return fmt.Errorf("chain_tags 含非法取值 %q:合法取值为 %s", t, strings.Join(Categories, "/"))
		}
	}
	if len(tags) > MaxTagsPerIntent {
		return fmt.Errorf("chain_tags 至多 %d 个(给了 %d 个):按主要攻击面打 1-2 个即可", MaxTagsPerIntent, len(tags))
	}
	return nil
}

// Skeleton 返回某分类的骨架文本;文件缺失/读取失败返回 ok=false(调用方静默降级)。
func Skeleton(category string) (string, bool) {
	if !Valid(category) {
		return "", false
	}
	b, err := skeletonFS.ReadFile(category + ".md")
	if err != nil {
		return "", false
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", false
	}
	return s, true
}

// keywordRules 是回退关键词匹配器(意图无 chain_tags 时用):意图文本/vulnclass
// 关键词 → 类别。纯函数、确定性;按表顺序取前 MaxTagsPerIntent 个命中类别。
// 关键词尽量用多字词降低误命中(如"栈"不单列,用"栈溢出")。
var keywordRules = []struct {
	cat      string
	keywords []string
}{
	{"patch", []string{"patch diff", "补丁差分", "补丁分析", "补丁对比", "n-day", "ghidriff", "diaphora"}},
	{"firmware", []string{"firmware", "固件", "binwalk", "squashfs", "ubifs", "嵌入式安全", "iot security", "iot pentest"}},
	{"audit", []string{"code audit", "code-audit", "source code security", "security code review", "源码审计", "代码审计", "白盒审计", "semgrep", "codeql", "gosec", "sast"}},
	{"web", []string{"sql", "注入", "xss", "ssrf", "ssti", "xxe", "反序列化", "文件上传", "上传点", "命令注入", "命令执行", "代码执行", "rce", "waf", "逻辑漏洞", "越权", "jwt", "文件包含", "目录遍历", "cms", "graphql", "bola", "bfla", "idor", "接口鉴权", "接口测试", "批量赋值", "mass assignment", "限速绕过", "rest api", "websocket"}},
	{"identity", []string{"saml", "oidc", "openid", "oauth", "sso", "单点登录", "身份联邦", "联邦登录", "账号接管", "account takeover", "redirect_uri", "assertion 篡改", "idp 元数据"}},
	{"cloud", []string{"k8s", "kubernetes", "云原生", "imds", "元数据凭据", "公开桶", "存储桶", "iam 角色", "iam 权限", "过度授权", "rbac", "eks", "gke", "serviceaccount", "云控制面"}},
	{"protocol", []string{"protobuf", "grpc", "协议逆向", "私有协议", "二进制协议", "pcap", "流量还原", "帧布局", "帧结构", "tlv", "mqtt", "kaitai", "dissector", "报文解析", "decode_raw"}},
	{"ad", []string{"kerberos", "域控", "ad域", "活动目录", "ntlm", "dcsync", "kerberoast", "委派", "adcs", "黄金票据", "白银票据", "as-rep", "域渗透", "域内", "密码喷洒"}},
	{"app", []string{"apk", "frida", "小程序", "安卓", "android", "ios", "抓包", "app"}},
	{"priv", []string{"提权", "权限提升", "privesc", "suid", "内核漏洞", "disable_functions", "容器逃逸", "逃逸"}},
	{"pwn", []string{"栈溢出", "堆溢出", "堆喷", "格式化字符串", "ctf", "pwn", "shellcode", "rop", "uaf", "double free", "tcache", "栈迁移"}},
	{"recon", []string{"侦察", "指纹", "子域", "信息收集", "osint", "端口扫描", "目录扫描", "资产测绘", "踩点", "敏感信息", "泄露"}},
	{"rev", []string{"逆向", "脱壳", "反编译", "加壳", "反调试", "混淆", "静态分析", "动态调试", "算法恢复"}},
	{"pivot", []string{"隧道", "代理", "横向", "内网", "穿透", "socks", "chisel", "frp", "端口转发", "跳板", "立足点", "webshell"}},
}

// matchesKeyword 以 ASCII 词边界匹配关键词,避免短 ASCII 词命中更长英文单词内部
// (如 sso⊂processor、eks⊂weeks、rce⊂source)。边界字节为 [a-z0-9_];中文/空格/
// 连字符等均视为边界,故中文关键词与多词关键词行为不变。
func matchesKeyword(text, keyword string) bool {
	isTokenByte := func(b byte) bool {
		return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '_'
	}
	for offset := 0; offset < len(text); {
		idx := strings.Index(text[offset:], keyword)
		if idx < 0 {
			return false
		}
		start := offset + idx
		end := start + len(keyword)
		if (start == 0 || !isTokenByte(text[start-1])) && (end == len(text) || !isTokenByte(text[end])) {
			return true
		}
		offset = end
	}
	return false
}

// Match 是回退关键词匹配器:从自由文本(意图 summary / vulnclass)推出至多
// MaxTagsPerIntent 个类别,无任何命中返回 nil(调用方静默不注入)。
func Match(text string) []string {
	text = strings.ToLower(text)
	if strings.TrimSpace(text) == "" {
		return nil
	}
	var out []string
	for _, r := range keywordRules {
		for _, kw := range r.keywords {
			if matchesKeyword(text, kw) {
				out = append(out, r.cat)
				break
			}
		}
		if len(out) >= MaxTagsPerIntent {
			break
		}
	}
	return out
}

// wrapSection 是 L3 骨架的轻量 section 标记(与 WrapUntrustedData 同款分区思路,
// 但语义相反:骨架是平台内置的【可信】内容,标记只为让模型分清"这是平台注入的
// 决策纪律"与目标/工人产出的不可信数据,不复用 untrusted 标签与措辞)。
func wrapSection(category, body string) string {
	safe := strings.ReplaceAll(body, "</chains-skeleton", "＜/chains-skeleton")
	return `<chains-skeleton source="chains-skeleton" category="` + category + `">` + "\n" + safe + "\n</chains-skeleton>"
}

// Section 把若干类别的骨架拼成注入 worker system 的区块:每类一个
// <chains-skeleton> 分区,总字符 cap sectionCapRunes(8K),超出截断并标注。
// 骨架缺失的类别静默跳过;最终为空返回 ""。
func Section(cats []string) string {
	header := "\n\n【反问决策链骨架(平台内置可信内容,非目标数据):按本意图攻击面注入的\"场景→判据→转向\"决策反射——探查受阻、下结论、判定真伪时对照自问;完整 Q&A 原文见对应 skills/chains-<类别>/refs/】"
	var b strings.Builder
	b.WriteString(header)
	used := len([]rune(header))
	truncated := false
	injected := 0
	for _, c := range cats {
		if injected >= MaxTagsPerIntent {
			break
		}
		sk, ok := Skeleton(c)
		if !ok {
			continue // 骨架缺失/读取失败:静默降级
		}
		sec := wrapSection(c, sk)
		secRunes := len([]rune(sec))
		if used+secRunes > sectionCapRunes {
			// 剩余空间放截断后的该骨架 + 标注;空间不足则整体截断。
			remain := sectionCapRunes - used
			if remain > 0 {
				r := []rune(sec)
				if remain > len(r) {
					remain = len(r)
				}
				b.WriteString(string(r[:remain]))
			}
			truncated = true
			break
		}
		b.WriteString("\n")
		used++ // 上面的换行
		b.WriteString(sec)
		used += secRunes
		injected++
	}
	if injected == 0 && !truncated {
		return ""
	}
	if truncated {
		mark := "\n…(骨架总长超 8K 已截断;完整原文见 skills/chains-<类别>/refs/)"
		b.WriteString(mark)
	}
	return b.String()
}

// intentCats 是 ForIntent/RefsGuideForIntent 共用的类别解析:优先取 chain_tags
// (规整后取首个合法值,非法值忽略);无合法 tags 时取首个确定性关键词匹配。
func intentCats(payload json.RawMessage) []string {
	var p struct {
		Summary   string   `json:"summary"`
		ChainTags []string `json:"chain_tags"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil
	}
	var cats []string
	for _, t := range NormalizeChainTags(p.ChainTags) {
		if Valid(t) {
			cats = append(cats, t)
		}
		if len(cats) > 0 {
			break
		}
	}
	if len(cats) == 0 {
		cats = Match(p.Summary)
	}
	if len(cats) > 1 {
		cats = cats[:1]
	}
	return cats
}

// ForIntent 从意图节点 payload 构建 L3 注入块:优先取 chain_tags(规整后取合法
// 的首个合法值);无 tags 时取首个 summary 关键词匹配;匹配不中或骨架
// 缺失返回 ""(不注入,不阻断 worker)。
func ForIntent(payload json.RawMessage) string {
	cats := intentCats(payload)
	if len(cats) == 0 {
		return ""
	}
	return Section(cats)
}
