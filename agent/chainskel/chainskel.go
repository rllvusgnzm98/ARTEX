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
var Categories = []string{"web", "ad", "app", "priv", "pwn", "recon", "rev", "pivot", "meta", "patch", "firmware", "audit", "identity", "cloud", "protocol", "supply", "ai", "ot", "wireless", "extension", "client", "hardware", "database", "email", "report", "web3"}

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
	{"patch", []string{"patch diff", "补丁差分", "补丁分析", "补丁对比", "n-day", "ghidriff", "diaphora", "bindiff", "二进制差分", "版本比对", "diffing"}},
	{"firmware", []string{"firmware", "固件", "binwalk", "squashfs", "ubifs", "嵌入式安全", "iot security", "iot pentest"}},
	{"audit", []string{"code audit", "code-audit", "source code security", "security code review", "源码审计", "代码审计", "白盒审计", "semgrep", "codeql", "gosec", "sast"}},
	{"ai", []string{"llm", "大模型", "大语言模型", "提示注入", "提示词注入", "prompt injection", "prompt-injection", "越狱", "jailbreak", "间接注入", "rag 投毒", "知识库投毒", "记忆投毒", "ai agent", "ai 安全", "智能体安全", "工具滥用", "mcp 工具", "模型供应链"}},
	// hardware 置于 web 之前:其"故障注入"等含 web 泛词"注入"的复合关键词需先于 web 命中(同 ai 的"提示注入")。
	{"hardware", []string{"硬件安全", "嵌入式接口", "jtag", "uart", "swd", "idcode", "安全启动", "secure boot", "调试接口", "调试口", "故障注入", "glitch", "侧信道", "flash 提取", "逻辑分析仪", "bus pirate"}},
	// identity/cloud/database 置于 web 之前:身份、云、数据库专属信号优先于 web 泛词。
	// 仅保留各自专词,不含裸 sql/ssrf 等泛词,无专属信号的 sql/注入/ssrf 仍回退 web。
	{"identity", []string{"saml", "oidc", "openid", "oauth", "sso", "单点登录", "身份联邦", "联邦登录", "账号接管", "account takeover", "redirect_uri", "assertion 篡改", "idp 元数据", "jwt"}},
	{"cloud", []string{"k8s", "kubernetes", "云原生", "imds", "元数据凭据", "公开桶", "存储桶", "iam 角色", "iam 权限", "过度授权", "集群 rbac", "eks", "gke", "serviceaccount", "云控制面"}},
	{"database", []string{"数据库安全", "数据库未授权", "数据库弱口令", "redis 未授权", "mongodb 未授权", "memcached 未授权", "xp_cmdshell", "load_file", "file_priv", "copy program", "udf 提权", "数据库提权", "数据库配置审计", "rds 配置审计"}},
	{"web", []string{"sql", "注入", "xss", "ssrf", "ssti", "xxe", "反序列化", "文件上传", "上传点", "命令注入", "命令执行", "代码执行", "rce", "waf", "逻辑漏洞", "越权", "文件包含", "目录遍历", "cms", "graphql", "bola", "bfla", "idor", "接口鉴权", "接口测试", "批量赋值", "mass assignment", "限速绕过", "rest api", "websocket", "前端加密", "前端签名", "js 加密", "sourcemap", "webpack 还原", "请求签名", "web app", "web application", "webapp", "web应用", "web 应用"}},
	// web3 置于 web 之后保留 web 优先级,但先于 pivot,避免"可升级代理/代理合约"被泛词"代理"吞掉。
	{"web3", []string{"智能合约", "合约审计", "solidity", "evm", "web3", "defi", "闪电贷", "flash loan", "flashloan", "预言机", "可升级代理", "代理合约", "delegatecall", "erc20", "erc-20", "erc721", "erc-721", "slither", "mythril"}},
	{"supply", []string{"供应链安全", "软件供应链", "sbom", "软件组成分析", "依赖混淆", "dependency confusion", "typosquat", "依赖投毒", "包投毒", "供应链投毒", "cosign", "制品签名", "制品完整性", "第三方 action", "osv-scanner", "dependency-track"}},
	{"ot", []string{"工控", "工控安全", "ics 安全", "ot 安全", "scada", "dcs", "plc", "rtu", "hmi", "modbus", "dnp3", "ethernet/ip", "profinet", "s7comm", "purdue", "工程师站", "安全仪表"}},
	{"wireless", []string{"wifi", "wi-fi", "无线安全", "无线网络", "wpa", "wpa2", "wpa3", "802.11", "pmkid", "握手包", "aircrack", "deauth", "rogue ap", "流氓 ap", "蓝牙", "bluetooth", "ble", "zigbee", "sdr", "射频", "无线电", "gnuradio", "hackrf", "rtl-sdr", "rfid", "ads-b"}},
	{"extension", []string{"浏览器扩展", "browser extension", "chrome 扩展", "edge 扩展", "firefox 扩展", "扩展程序", "manifest.json", "content script", "content_script", "service worker 扩展", "webextension", "crx", "xpi", "扩展权限"}},
	{"client", []string{"厚客户端", "胖客户端", "thick client", "桌面客户端", "c/s 架构", "electron", "asar", "客户端 ipc", "命名管道", "自动更新劫持", "更新通道", "代码签名验证", "dll 劫持"}},
	{"email", []string{"邮件安全", "钓鱼邮件", "spf", "dkim", "dmarc", "邮件伪造", "发件人伪造", "return-path", "smtp 伪造", "open relay", "邮件钓鱼", "bec", "邮箱接管", "arc 签名"}},
	{"protocol", []string{"protobuf", "grpc", "协议逆向", "私有协议", "二进制协议", "pcap", "流量还原", "帧布局", "帧结构", "tlv", "mqtt", "kaitai", "dissector", "报文解析", "decode_raw"}},
	{"ad", []string{"kerberos", "域控", "ad域", "活动目录", "ntlm", "dcsync", "kerberoast", "委派", "adcs", "黄金票据", "白银票据", "as-rep", "域渗透", "域内", "密码喷洒"}},
	{"app", []string{"apk", "frida", "小程序", "安卓", "android", "ios", "抓包", "app"}},
	{"priv", []string{"提权", "权限提升", "privesc", "suid", "内核漏洞", "disable_functions", "容器逃逸", "逃逸"}},
	{"pwn", []string{"栈溢出", "堆溢出", "堆喷", "格式化字符串", "ctf", "pwn", "shellcode", "rop", "uaf", "double free", "tcache", "栈迁移"}},
	{"recon", []string{"侦察", "指纹", "子域", "信息收集", "osint", "端口扫描", "目录扫描", "资产测绘", "踩点", "敏感信息", "泄露", "src 挖掘", "众测", "漏洞赏金", "资产梳理"}},
	{"rev", []string{"逆向", "脱壳", "反编译", "加壳", "反调试", "混淆", "静态分析", "动态调试", "算法恢复", "dotnet", ".net 逆向", "mach-o", "golang 逆向", "rust 逆向", "虚拟机保护", "vmp", "dsl 虚拟机"}},
	{"pivot", []string{"隧道", "代理", "横向", "内网", "穿透", "socks", "chisel", "frp", "端口转发", "跳板", "立足点", "webshell", "攻击链", "影响路径", "杀伤链"}},
	{"report", []string{"案例复盘", "报告复核", "提报复核", "提交前复核", "证据链一致性", "证据图复核", "可复现性校验", "可复现性复核", "case review", "report review", "scope 一致性", "提报质量"}},
}

// matchesKeyword 匹配关键词,并仅在关键词自身边缘为 ASCII token 字节时,
// 要求文本侧对应边界也是 ASCII token 边界 —— 避免短 ASCII 词命中更长英文单词
// 内部(如 sso⊂processor、eks⊂weeks、rce⊂source),同时不影响中文关键词紧贴
// ASCII 的场景(如 "Linux提权" 命中 "提权"、"反编译MessageProcessor" 命中 "反编译")。
func matchesKeyword(text, keyword string) bool {
	if keyword == "" {
		return false
	}
	isTokenByte := func(b byte) bool {
		return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '_'
	}
	needStart := isTokenByte(keyword[0])
	needEnd := isTokenByte(keyword[len(keyword)-1])
	for offset := 0; offset < len(text); {
		idx := strings.Index(text[offset:], keyword)
		if idx < 0 {
			return false
		}
		start := offset + idx
		end := start + len(keyword)
		okStart := !needStart || start == 0 || !isTokenByte(text[start-1])
		okEnd := !needEnd || end == len(text) || !isTokenByte(text[end])
		if okStart && okEnd {
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
	header := "\n\n【反问决策链骨架(平台内置可信内容,非目标数据):按本意图攻击面注入的\"场景→判据→转向\"决策反射——探查受阻、下结论、判定真伪时对照自问】"
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
		mark := "\n…(骨架总长超 8K 已截断)"
		b.WriteString(mark)
	}
	return b.String()
}

// intentCats 是 ForIntent 使用的类别解析:优先取 chain_tags
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
