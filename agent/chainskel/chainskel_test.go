package chainskel

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestValidateChainTags(t *testing.T) {
	cases := []struct {
		name    string
		tags    []string
		wantErr bool
	}{
		{"nil 合法", nil, false},
		{"单个合法", []string{"web"}, false},
		{"两个合法", []string{"web", "pivot"}, false},
		{"非法取值", []string{"web", "bogus"}, true},
		{"超过两个", []string{"web", "ad", "priv"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateChainTags(c.tags)
			if (err != nil) != c.wantErr {
				t.Fatalf("ValidateChainTags(%v) err=%v, wantErr=%v", c.tags, err, c.wantErr)
			}
		})
	}
}

func TestNormalizeChainTags(t *testing.T) {
	got := NormalizeChainTags([]string{" Web ", "web", "PIVOT", "", "  "})
	want := []string{"web", "pivot"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestMatch(t *testing.T) {
	cases := []struct {
		text string
		want []string // nil 表示期望无命中
	}{
		{"对 /api/user?id=1 做 sql 注入测试", []string{"web"}},
		{"域内 kerberos 委派滥用摸底", []string{"ad"}},
		{" webshell 落地后搭隧道做内网横向 ", []string{"pivot"}},
		{"Linux 提权:先查 suid 与内核漏洞", []string{"priv"}},
		{"ctf pwn 题,栈溢出 + rop", []string{"pwn"}},
		{"子域收集与指纹识别等侦察工作", []string{"recon"}},
		{"逆向该样本,先脱壳再静态分析", []string{"rev"}},
		{"apk 抓包受阻,上 frida hook", []string{"app"}},
		{"对该接口做 sql 注入,拿到后提权", []string{"web", "priv"}}, // 多命中,按规则表顺序取前 2
		{"常规巡检,无明确攻击面", nil},
		{"", nil},
	}
	for _, c := range cases {
		got := Match(c.text)
		if len(got) != len(c.want) {
			t.Fatalf("Match(%q)=%v, want %v", c.text, got, c.want)
		}
		for i := range c.want {
			if got[i] != c.want[i] {
				t.Fatalf("Match(%q)=%v, want %v", c.text, got, c.want)
			}
		}
	}
}

func primarySkeletonCategory(out string) string {
	const prefix = `<chains-skeleton source="chains-skeleton" category="`
	idx := strings.Index(out, prefix)
	if idx < 0 {
		return ""
	}
	rest := out[idx+len(prefix):]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return ""
	}
	return rest[:end]
}

func TestP1RoutingMismatches(t *testing.T) {
	for _, tc := range []struct {
		summary  string
		tags     []string
		category string
	}{
		{"JWT OAuth 令牌信任评估", nil, "identity"},
		{"JWT 令牌伪造", nil, "identity"},
		{"jwt", nil, "identity"},
		{"OIDC SSO 单点登录绕过", nil, "identity"},
		{"SAML 断言签名绕过", nil, "identity"},
		{"SSRF 打云元数据 IMDS 临时凭据", nil, "cloud"},
		{"SSRF 读取 IMDS", nil, "cloud"},
		{"REST API RBAC 评估", nil, "web"},
		{"k8s 集群 rbac 审查", nil, "cloud"},
		{"SSRF 文件读取", nil, "web"},
		{"SQL 数据库配置审计", nil, "database"},
		{"数据库未授权与危险配置审计", nil, "database"},
		{"对 /api 做 sql 注入测试", nil, "web"},
		{"域内横向移动摸底", nil, "ad"},
		{"域渗透 kerberos 委派滥用", nil, "ad"},
		{"web app 渗透测试", nil, "web"},
		{"webapp 逻辑漏洞挖掘", nil, "web"},
		{"web application 渗透测试", nil, "web"},
		{"web应用 渗透测试", nil, "web"},
		{"web 应用 渗透测试", nil, "web"},
		{"SQLi", nil, ""},
		{"OAuth2", nil, ""},
		{"常规巡检,无明确攻击面", nil, ""},
		{"单写 CVE bounty 信息", nil, ""},
		{"task planned for three weeks", nil, ""},
		{"grep the sourcecode", nil, ""},
		{"反编译 MessageProcessor", nil, "rev"},
		{"invalid tag", []string{"bogus"}, ""},
		{"做 sql 注入测试", []string{"identity", "web"}, "identity"},
		{"x", []string{"web", "cloud"}, "web"},
		{"explicit meta", []string{"meta"}, "meta"},
	} {
		t.Run(tc.summary, func(t *testing.T) {
			out := ForIntent(payload(t, map[string]any{"summary": tc.summary, "chain_tags": tc.tags}))
			if tc.category == "" {
				if out != "" {
					t.Fatalf("irrelevant intent routed: %s", out)
				}
				return
			}
			n := strings.Count(out, "<chains-skeleton ")
			if primarySkeletonCategory(out) != tc.category || n < 1 || n > MaxTagsPerIntent {
				t.Fatalf("wrong primary skeleton, want %s (count 1..%d, got %d): %s", tc.category, MaxTagsPerIntent, n, out)
			}
		})
	}
	for _, category := range []string{"identity", "cloud", "database"} {
		if err := ValidateChainTags([]string{category, "web"}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSkeletonEmbedded(t *testing.T) {
	for _, c := range Categories {
		sk, ok := Skeleton(c)
		if !ok {
			t.Fatalf("类别 %s 骨架缺失(go:embed 应保证 9 类全在)", c)
		}
		if !strings.Contains(sk, "场景") || !strings.Contains(sk, "判据") {
			t.Fatalf("类别 %s 骨架不含 场景/判据 字段,疑似内容错误", c)
		}
	}
	if _, ok := Skeleton("nope"); ok {
		t.Fatal("非法类别应返回 ok=false")
	}
}

func payload(t *testing.T, m map[string]any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestForIntentByTags(t *testing.T) {
	out := ForIntent(payload(t, map[string]any{"summary": "打某站", "chain_tags": []string{"web"}}))
	if !strings.Contains(out, `<chains-skeleton source="chains-skeleton" category="web">`) {
		t.Fatalf("按 chain_tags 注入失败:\n%s", out)
	}
	if strings.Contains(out, "untrusted-data") {
		t.Fatal("骨架分区不得复用 untrusted 语义标签")
	}
}

func TestForIntentUpToTwoTags(t *testing.T) {
	out := ForIntent(payload(t, map[string]any{"summary": "x", "chain_tags": []string{"web", "ad", "pivot"}}))
	if primarySkeletonCategory(out) != "web" || !strings.Contains(out, `category="ad"`) || strings.Count(out, "<chains-skeleton ") != MaxTagsPerIntent {
		t.Fatalf("应按序注入前 %d 个合法 tag (web, ad):\n%s", MaxTagsPerIntent, out)
	}
	if strings.Contains(out, `category="pivot"`) {
		t.Fatal("第 3 个 tag 超出 MaxTagsPerIntent,不应注入")
	}
}

func TestForIntentInvalidTagFallsBack(t *testing.T) {
	// 非法 tag 被忽略;剩余无合法 tag 时回退到 summary 关键词匹配。
	out := ForIntent(payload(t, map[string]any{"summary": "做 sql 注入测试", "chain_tags": []string{"bogus"}}))
	if !strings.Contains(out, `category="web"`) {
		t.Fatalf("非法 tag 应回退关键词匹配注入 web:\n%s", out)
	}
}

func TestForIntentNoTagKeywordFallback(t *testing.T) {
	out := ForIntent(payload(t, map[string]any{"summary": "内网隧道选型与横向"}))
	if !strings.Contains(out, `category="pivot"`) {
		t.Fatalf("无 tags 应关键词回退注入 pivot:\n%s", out)
	}
}

func TestForIntentNoMatchSilent(t *testing.T) {
	if out := ForIntent(payload(t, map[string]any{"summary": "随便看看"})); out != "" {
		t.Fatalf("匹配不中应静默不注入, got:\n%s", out)
	}
	if out := ForIntent(json.RawMessage(`{bad json`)); out != "" {
		t.Fatal("payload 解析失败应静默不注入")
	}
	if out := ForIntent(payload(t, map[string]any{"chain_tags": []string{"bogus"}})); out != "" {
		t.Fatal("tags 全非法且 summary 无关键词应静默不注入")
	}
}

func TestSectionTruncation(t *testing.T) {
	defer func(orig int) { sectionCapRunes = orig }(sectionCapRunes)
	sectionCapRunes = 600 // 调小上限,强制截断
	out := Section([]string{"web", "ad"})
	if out == "" {
		t.Fatal("截断后仍应有内容")
	}
	if !strings.Contains(out, "已截断") {
		t.Fatalf("超出 cap 应有截断标注:\n%s", out)
	}
	if strings.Contains(out, "/refs/") {
		t.Fatal("truncation must not advertise unavailable refs")
	}
	if n := len([]rune(out)); n > sectionCapRunes+80 { // 标注本身另算,给足余量
		t.Fatalf("截断后总长 %d 远超 cap %d", n, sectionCapRunes)
	}
}

func TestSectionMissingCategoryDegrades(t *testing.T) {
	// 非法类别(骨架必缺失)被静默跳过;有效类别仍注入。
	out := Section([]string{"nope", "web"})
	if !strings.Contains(out, `category="web"`) {
		t.Fatalf("缺失类别应跳过、有效类别照常注入:\n%s", out)
	}
	if strings.Contains(out, "nope") {
		t.Fatal("缺失类别不应出现在输出里")
	}
	if Section([]string{"nope"}) != "" {
		t.Fatal("全部缺失应返回空串(不注入)")
	}
}

func TestOnDemandCategories(t *testing.T) {
	for _, tc := range []struct{ summary, category string }{
		{"Patch diff CVE reproduction with SQL injection", "patch"},
		{"补丁差分验证 CNVD", "patch"},
		{"Firmware management RCE review", "firmware"},
		{"固件 squashfs 分析", "firmware"},
		{"Code audit for SQL injection", "audit"},
		{"代码审计鉴权", "audit"},
	} {
		t.Run(tc.summary, func(t *testing.T) {
			out := ForIntent(payload(t, map[string]any{"summary": tc.summary}))
			n := strings.Count(out, "<chains-skeleton ")
			if primarySkeletonCategory(out) != tc.category || n < 1 || n > MaxTagsPerIntent {
				t.Fatalf("wrong primary skeleton: %s", out)
			}
		})
	}
	for _, summary := range []string{"patch the documentation", "audit logging retention", "dispatch events", "auditor meeting", "CVE reproduction", "CVE 复现", "CVE复现", "CNVD reproduction", "CNVD 复现", "CNVD复现", ""} {
		if out := ForIntent(payload(t, map[string]any{"summary": summary})); out != "" {
			t.Fatalf("irrelevant intent %q routed: %s", summary, out)
		}
	}
	for _, category := range []string{"patch", "firmware", "audit", "identity", "cloud", "protocol"} {
		if err := ValidateChainTags([]string{category, "web"}); err != nil {
			t.Fatal(err)
		}
		p := payload(t, map[string]any{"summary": "sql injection", "chain_tags": []string{"bogus", " " + strings.ToUpper(category) + " ", "web"}})
		out := ForIntent(p)
		if primarySkeletonCategory(out) != category || !strings.Contains(out, `category="web"`) || strings.Count(out, "<chains-skeleton ") != 2 {
			t.Fatalf("dual valid tags lost: %s", out)
		}
		if len([]rune(out)) > 8000 || strings.Contains(out, "总长超 8K 已截断") {
			t.Fatalf("dual skeleton exceeds default budget: %s", category)
		}
		if guide := RefsGuideForIntent(p); guide != "" {
			t.Fatalf("distilled category has no bundled L4 refs: %s", guide)
		}
		sk, _ := Skeleton(category)
		lines := strings.Split(sk, "\n")
		if !strings.Contains(lines[1], "auth.status=granted") || !strings.Contains(lines[1], "不得强制或绕过") {
			t.Fatalf("missing first scope gate: %s", category)
		}
		if !strings.Contains(lines[1], "仓库脚本") || !strings.Contains(lines[1], "准确命令及副作用") || !strings.Contains(lines[1], "单独明确同意") {
			t.Fatalf("missing separate script approval gate: %s", category)
		}
		for _, term := range []string{"Evidence", "Finding", "Path", "SHA-256", "复现", "脱敏"} {
			// Source audits pin the file hash rather than a firmware image digest.
			if category == "audit" && term == "SHA-256" {
				term = "文件哈希"
			}
			if !strings.Contains(sk, term) {
				t.Fatalf("%s missing %s", category, term)
			}
		}
	}
}

func TestBatch2Categories(t *testing.T) {
	for _, tc := range []struct{ summary, category string }{
		{"OAuth redirect_uri 账号接管", "identity"},
		{"SAML 断言签名绕过", "identity"},
		{"k8s 集群 RBAC 审查", "cloud"},
		{"云元数据 IMDS 临时凭据", "cloud"},
		{"protobuf 报文解析字段还原", "protocol"},
		{"grpc 帧布局分析", "protocol"},
	} {
		t.Run(tc.summary, func(t *testing.T) {
			out := ForIntent(payload(t, map[string]any{"summary": tc.summary}))
			if !strings.Contains(out, `category="`+tc.category+`"`) || strings.Count(out, "<chains-skeleton ") != 1 {
				t.Fatalf("summary %q want primary %s, got: %s", tc.summary, tc.category, out)
			}
		})
	}
	// explicit chain_tags take priority over summary keywords, up to MaxTagsPerIntent blocks in order
	out := ForIntent(payload(t, map[string]any{"summary": "做 sql 注入测试", "chain_tags": []string{"cloud", "web"}}))
	if primarySkeletonCategory(out) != "cloud" || !strings.Contains(out, `category="web"`) || strings.Count(out, "<chains-skeleton ") != 2 {
		t.Fatalf("explicit tag priority failed: %s", out)
	}
	// api-security folds into the existing web tag (BOLA/GraphQL keywords route to web)
	for _, s := range []string{"GraphQL 内省与批查询 DoS", "REST API BOLA 越权"} {
		if o := ForIntent(payload(t, map[string]any{"summary": s})); !strings.Contains(o, `category="web"`) {
			t.Fatalf("api-security summary %q should route to web: %s", s, o)
		}
	}
	// missing-file / invalid behavior stays fail-closed for the new tags too
	if o := ForIntent(payload(t, map[string]any{"chain_tags": []string{"bogus"}})); o != "" {
		t.Fatal("all-invalid tags must stay silent")
	}
}

func TestForIntentPrimaryTruncation(t *testing.T) {
	defer func(orig int) { sectionCapRunes = orig }(sectionCapRunes)
	sectionCapRunes = 600
	out := ForIntent(payload(t, map[string]any{"chain_tags": []string{"firmware", "web"}}))
	if !strings.Contains(out, "已截断") || len([]rune(out)) > sectionCapRunes+80 || strings.Contains(out, `category="web"`) {
		t.Fatalf("primary skeleton truncation failed: %s", out)
	}
}

func TestAmbiguousLatinKeywordBoundaries(t *testing.T) {
	for _, tc := range []struct {
		summary string
		want    string
	}{
		{"seven-day log retention", ""},
		{"SQL injection in disaster recovery", "web"},
		{"n-day patch validation", "patch"},
		{"Run SAST for SQL injection", "audit"},
		{"N-day补丁分析", "patch"},
		{"SAST代码审计", "audit"},
		{"n-days", ""},
		{"sast_report", ""},
		{"seven-day then n-day", "patch"},
		{"disaster then SAST", "audit"},
		{"反编译 MessageProcessor", "rev"},      // sso ⊂ processor must not route identity
		{"task planned for three weeks", ""}, // eks ⊂ weeks must not route cloud
		{"grep the sourcecode", ""},          // rce ⊂ sourcecode must not route web
		{"oauth 账号接管", "identity"},           // standalone latin token still matches
		{"k8s 逃逸", "cloud"},
		{"Linux提权", "priv"},            // 中文词紧贴 ASCII 仍需命中
		{"反编译MessageProcessor", "rev"}, // 中文词在前,ASCII 紧随其后
	} {
		t.Run(tc.summary, func(t *testing.T) {
			out := ForIntent(payload(t, map[string]any{"summary": tc.summary}))
			if tc.want == "" {
				if out != "" {
					t.Fatalf("unexpected skeleton: %s", out)
				}
				return
			}
			n := strings.Count(out, "<chains-skeleton ")
			if primarySkeletonCategory(out) != tc.want || n < 1 || n > MaxTagsPerIntent {
				t.Fatalf("want primary %s, got %s", tc.want, out)
			}
		})
	}
}

func TestWeb3Skeleton(t *testing.T) {
	for _, tc := range []struct{ summary, category string }{
		{"Solidity 智能合约重入审计", "web3"},
		{"DeFi 协议预言机价格操纵评估", "web3"},
		{"闪电贷放大清算逻辑", "web3"},
		{"可升级代理合约存储冲突", "web3"},
		{"delegatecall 目标可控性", "web3"},
		{"Solidity EIP-712 签名重放与 nonce 重放", "web3"},
		{"slither 合约审计", "web3"},
		{"socks 代理搭建内网横向", "pivot"},
		{"web 渗透常规巡检", ""},
		{"define the token contract interface", ""},
		{"sql 注入与智能合约", "web"},
		{"OIDC 签名重放", "identity"},
		{"Android 组件重入", "app"},
		{"reentrancy in kernel driver", ""},
		{"支付价格操纵逻辑漏洞", "web"},
		{"数据库存储冲突排查", ""},
	} {
		t.Run(tc.summary, func(t *testing.T) {
			out := ForIntent(payload(t, map[string]any{"summary": tc.summary}))
			if tc.category == "" {
				if out != "" {
					t.Fatalf("unexpected skeleton: %s", out)
				}
				return
			}
			n := strings.Count(out, "<chains-skeleton ")
			if primarySkeletonCategory(out) != tc.category || n < 1 || n > MaxTagsPerIntent {
				t.Fatalf("summary %q want primary %s, got: %s", tc.summary, tc.category, out)
			}
		})
	}
	if !Valid("web3") {
		t.Fatal("web3 not registered in Categories")
	}
	if err := ValidateChainTags([]string{"web3", "web"}); err != nil {
		t.Fatal(err)
	}
	for _, tags := range [][]string{{"web3", "web"}, {"bogus", " WEB3 ", "web"}} {
		p := payload(t, map[string]any{"summary": "做 sql 注入测试", "chain_tags": tags})
		out := ForIntent(p)
		if primarySkeletonCategory(out) != "web3" || !strings.Contains(out, `category="web"`) || strings.Count(out, "<chains-skeleton ") != 2 {
			t.Fatalf("explicit tag priority failed: %s", out)
		}
		if len([]rune(out)) > 8000 || strings.Contains(out, "总长超 8K 已截断") {
			t.Fatal("web3+web skeleton exceeds default budget")
		}
		if guide := RefsGuideForIntent(p); guide != "" {
			t.Fatalf("distilled category must have no bundled L4 refs: %s", guide)
		}
	}
	sk, ok := Skeleton("web3")
	if !ok {
		t.Fatal("missing web3 skeleton")
	}
	lines := strings.Split(sk, "\n")
	if len(lines) < 2 {
		t.Fatal("missing first scope gate")
	}
	for _, term := range []string{"auth.status=granted", "不得强制或绕过", "仓库脚本", "准确命令及副作用", "单独明确同意"} {
		if !strings.Contains(lines[1], term) {
			t.Fatalf("first scope gate missing %s", term)
		}
	}
	for _, term := range []string{"Evidence", "Finding", "Path", "SHA-256", "复现", "脱敏"} {
		if !strings.Contains(sk, term) {
			t.Fatalf("web3 missing %s", term)
		}
	}
	if out := ForIntent(payload(t, map[string]any{"chain_tags": []string{"bogus"}})); out != "" {
		t.Fatalf("all-invalid tags must stay silent: %s", out)
	}
	if out := Section([]string{"nope"}); out != "" {
		t.Fatalf("invalid category must stay silent: %s", out)
	}
	if _, ok := Skeleton("web3x"); ok {
		t.Fatal("invalid skeleton must fail closed")
	}
	defer func(orig int) { sectionCapRunes = orig }(sectionCapRunes)
	sectionCapRunes = 600
	out := ForIntent(payload(t, map[string]any{"chain_tags": []string{"web3", "web"}}))
	if !strings.Contains(out, "已截断") || len([]rune(out)) > sectionCapRunes+80 || strings.Contains(out, `category="web"`) {
		t.Fatalf("primary skeleton truncation failed: %s", out)
	}
}

func TestBatch3NewTags(t *testing.T) {
	for _, tc := range []struct{ summary, category string }{
		{"软件供应链 SBOM 依赖混淆排查", "supply"},
		{"cosign 制品签名与依赖投毒", "supply"},
		{"LLM 提示注入与系统提示词提取", "ai"},
		{"ai agent 工具滥用越权调用", "ai"},
		{"工控 SCADA Modbus 暴露面评估", "ot"},
		{"PLC 寄存器与 Purdue 分区", "ot"},
		{"WiFi WPA 握手包离线口令评估", "wireless"},
		{"SDR 射频信号解调分析", "wireless"},
		{"浏览器扩展 manifest.json 权限面审查", "extension"},
		{"crx 解包与 content script 分析", "extension"},
		{"Electron 桌面客户端 ipc 与自动更新劫持", "client"},
		{"厚客户端 dll 劫持与本地凭据", "client"},
		{"JTAG 调试接口与安全启动评估", "hardware"},
		{"JTAG 故障注入评估", "hardware"}, // 故障注入 含 web 的"注入",须路由 hardware 而非 web
		{"硬件安全 flash 提取与哈希保全", "hardware"},
		{"数据库未授权与危险配置审计", "database"},
		{"xp_cmdshell 与 file_priv 危险功能", "database"},
		{"SPF DKIM DMARC 对齐与邮件伪造", "email"},
		{"钓鱼邮件 BEC 与邮箱接管", "email"},
		{"案例复盘与证据链一致性复核", "report"},
		{"report review 与 scope 一致性", "report"},
	} {
		t.Run(tc.summary, func(t *testing.T) {
			out := ForIntent(payload(t, map[string]any{"summary": tc.summary}))
			n := strings.Count(out, "<chains-skeleton ")
			if primarySkeletonCategory(out) != tc.category || n < 1 || n > MaxTagsPerIntent {
				t.Fatalf("summary %q want primary %s, got: %s", tc.summary, tc.category, out)
			}
		})
	}
	// explicit chain_tags take priority over summary keywords, up to MaxTagsPerIntent blocks in order
	out := ForIntent(payload(t, map[string]any{"summary": "做 sql 注入测试", "chain_tags": []string{"ai", "web"}}))
	if primarySkeletonCategory(out) != "ai" || !strings.Contains(out, `category="web"`) || strings.Count(out, "<chains-skeleton ") != 2 {
		t.Fatalf("explicit new-tag priority failed: %s", out)
	}
	// all-invalid tags stay fail-closed (no L3 injection)
	if o := ForIntent(payload(t, map[string]any{"chain_tags": []string{"bogus"}})); o != "" {
		t.Fatal("all-invalid tags must stay silent")
	}
}

func TestBatch3Folds(t *testing.T) {
	for _, tc := range []struct{ summary, category string }{
		{"bindiff 定位改动函数做差分", "patch"},       // binary-diff -> patch
		{"前端请求签名还原与 js 加密", "web"},           // js-reverse -> web
		{"apk 静态脱壳分析", "app"},                // apk-reverse -> app (app 先于 rev)
		{"iOS 运行时 hook 校验绕过", "app"},         // mobile-reverse -> app
		{"Mach-O 代码签名与 dotnet 程序集逆向", "rev"}, // macos/dotnet-reverse -> rev
		{"golang 逆向 stripped 二进制", "rev"},    // go-rust-reverse -> rev
		{"虚拟机保护 vmp 还原", "rev"},              // dsl-vm-reverse -> rev
		{"攻击链串联内网横向", "pivot"},               // attack-chain -> pivot
		{"堆溢出 tcache 利用链", "pwn"},            // pwn-chain -> pwn
		{"活动目录 kerberoast 委派滥用", "ad"},       // windows-ad -> ad
		{"src 众测资产梳理与信息收集", "recon"},         // src-hunter -> recon
	} {
		t.Run(tc.summary, func(t *testing.T) {
			out := ForIntent(payload(t, map[string]any{"summary": tc.summary}))
			n := strings.Count(out, "<chains-skeleton ")
			if primarySkeletonCategory(out) != tc.category || n < 1 || n > MaxTagsPerIntent {
				t.Fatalf("fold summary %q want %s, got: %s", tc.summary, tc.category, out)
			}
		})
	}
}

func TestBatch3SkeletonDiscipline(t *testing.T) {
	for _, category := range []string{"supply", "ai", "ot", "wireless", "extension", "client", "hardware", "database", "email", "report"} {
		if !Valid(category) {
			t.Fatalf("new category %s not registered in Categories", category)
		}
		if err := ValidateChainTags([]string{category, "web"}); err != nil {
			t.Fatal(err)
		}
		p := payload(t, map[string]any{"summary": "sql injection", "chain_tags": []string{"bogus", " " + strings.ToUpper(category) + " ", "web"}})
		out := ForIntent(p)
		if primarySkeletonCategory(out) != category || !strings.Contains(out, `category="web"`) || strings.Count(out, "<chains-skeleton ") != 2 {
			t.Fatalf("dual valid tags lost: %s -> %s", category, out)
		}
		if len([]rune(out)) > 8000 || strings.Contains(out, "总长超 8K 已截断") {
			t.Fatalf("dual skeleton exceeds default budget: %s", category)
		}
		if guide := RefsGuideForIntent(p); guide != "" {
			t.Fatalf("distilled category must have no bundled L4 refs: %s -> %s", category, guide)
		}
		sk, ok := Skeleton(category)
		if !ok {
			t.Fatalf("missing skeleton: %s", category)
		}
		lines := strings.Split(sk, "\n")
		if !strings.Contains(lines[1], "auth.status=granted") || !strings.Contains(lines[1], "不得强制或绕过") {
			t.Fatalf("missing first scope gate: %s", category)
		}
		if !strings.Contains(lines[1], "仓库脚本") || !strings.Contains(lines[1], "准确命令及副作用") || !strings.Contains(lines[1], "单独明确同意") {
			t.Fatalf("missing separate script approval gate: %s", category)
		}
		for _, term := range []string{"Evidence", "Finding", "Path", "SHA-256", "复现", "脱敏"} {
			if !strings.Contains(sk, term) {
				t.Fatalf("%s missing %s", category, term)
			}
		}
	}
}

func TestSkillGuideForIntentAndExpandedWebKeywords(t *testing.T) {
	p := payload(t, map[string]any{"summary": "PrestaShop 8.1.5 漏洞利用", "chain_tags": []string{"web"}})
	guide := SkillGuideForIntent(p)
	for _, want := range []string{"target-health-triage", "oss-cms-patch-audit", "async-client-oob-chain", "oob_allocate"} {
		if !strings.Contains(guide, want) {
			t.Fatalf("SkillGuideForIntent missing %q: %s", want, guide)
		}
	}
	// Summary-only CMS/OSS fallback routes to web even when chain_tags is omitted.
	out := ForIntent(payload(t, map[string]any{"summary": "WordPress Business Directory 插件分析"}))
	if primarySkeletonCategory(out) != "web" {
		t.Fatalf("expected WordPress summary to route to web, got: %s", out)
	}
	// Irrelevant summary stays silent.
	if empty := SkillGuideForIntent(payload(t, map[string]any{"summary": "常规巡检,无明确攻击面"})); empty != "" {
		t.Fatalf("expected empty SkillGuideForIntent for unmatched summary, got: %s", empty)
	}
}

// 技能提示必须携带 frontmatter description（路由决策依据），而非裸名字。
// 回归依据：复盘里 worker 面对 target-health-triage / blind-oracle-extractor
// 这类名字无法判断何时该加载，提示只给一行技能名等于没给。
func TestSkillGuideCarriesDescriptions(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ARTEX_SKILL_DIR", dir)
	writeTestSkill := func(name, desc string) {
		sub := dir + "/" + name
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		body := "---\nname: " + name + "\ndescription: " + desc + "\n---\n正文\n"
		if err := os.WriteFile(sub+"/SKILL.md", []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeTestSkill("target-health-triage", "目标 502/503/全站拦截或限速时的健康分诊与降级路线技能。")

	guide := SkillGuideForIntent(payload(t, map[string]any{"summary": "x", "chain_tags": []string{"web"}}))
	if !strings.Contains(guide, "target-health-triage — 目标 502/503") {
		t.Fatalf("guide must carry the skill description inline, got: %s", guide)
	}
	// 目录里没有的技能名降级为裸名、不消失。
	if !strings.Contains(guide, "oss-cms-patch-audit") {
		t.Fatalf("skills without on-disk description must still be listed by name, got: %s", guide)
	}

	// 超长描述按字符截断并带省略号，防止 prompt 膨胀。
	long := strings.Repeat("长", skillDescriptionTrunc+50)
	writeTestSkill("oss-cms-patch-audit", long)
	guide2 := SkillGuideForIntent(payload(t, map[string]any{"summary": "x", "chain_tags": []string{"web"}}))
	if strings.Contains(guide2, long) {
		t.Fatalf("description must be truncated at %d runes", skillDescriptionTrunc)
	}
	if !strings.Contains(guide2, "…") {
		t.Fatalf("truncated description must carry ellipsis, got: %s", guide2)
	}
}

// 技能目录缺失/不可读时静默降级为裸名清单（同改动前），绝不阻断意图渲染。
func TestSkillGuideDegradesWithoutSkillDir(t *testing.T) {
	t.Setenv("ARTEX_SKILL_DIR", t.TempDir()+"/does-not-exist")
	// config.SkillDir 会创建缺失目录，所以这里目录会被建出来但为空：
	// 空目录 = 没有技能 = 全裸名，同样验证降级路径。
	guide := SkillGuideForIntent(payload(t, map[string]any{"summary": "x", "chain_tags": []string{"web"}}))
	if !strings.Contains(guide, "target-health-triage") {
		t.Fatalf("bare-name fallback must still list skills, got: %s", guide)
	}
	if strings.Contains(guide, " — ") {
		t.Fatalf("empty skill dir must not render any description, got: %s", guide)
	}
}

func TestSkillGuideHonorsVisibilityResolver(t *testing.T) {
	prev := SkillCatalogResolver
	t.Cleanup(func() { SkillCatalogResolver = prev })
	SkillCatalogResolver = func(agentKey string) (map[string]bool, map[string]string) {
		return map[string]bool{
				"target-health-triage": true,
			}, map[string]string{
				"target-health-triage": "3 点对照快速分诊 502/503/WAF",
				"playwright-cli":       "已禁用技能不应泄露",
			}
	}
	guide := SkillGuideForIntent(payload(t, map[string]any{"summary": "x", "chain_tags": []string{"web"}}))
	if !strings.Contains(guide, "target-health-triage — 3 点对照快速分诊") {
		t.Fatalf("visible skill description missing: %s", guide)
	}
	if strings.Contains(guide, "playwright-cli") || strings.Contains(guide, "oss-cms-patch-audit") {
		t.Fatalf("disabled/unbound skills must not be advertised: %s", guide)
	}
	if !strings.Contains(guide, "oob_allocate") {
		t.Fatalf("managed OOB note must remain even when last skill is disabled: %s", guide)
	}
}

func TestSkillGuideWebLogicInternalReconAndMultiTag(t *testing.T) {
	// 1. WebLogic intent surfaces weblogic-java-rce both via priority keyword & web category.
	wl := SkillGuideForIntent(payload(t, map[string]any{
		"summary":    "经跳板破袭 192.168.3.34:7001 WebLogic wls-wsat CVE-2017-10271",
		"chain_tags": []string{"web"},
	}))
	if !strings.Contains(wl, "weblogic-java-rce") || !strings.Contains(wl, "[高匹配]") {
		t.Fatalf("WebLogic intent must highlight weblogic-java-rce: %s", wl)
	}

	// 2. Internal single-IP host recon must NOT advertise external enterprise domain/SPA skills.
	lanRecon := SkillGuideForIntent(payload(t, map[string]any{
		"summary":    "广度侦察哨：对唯一目标 192.168.111.79 做 TCP 全端口、SMB/WinRM/RDP 识别",
		"chain_tags": []string{"recon"},
	}))
	if strings.Contains(lanRecon, "tbhm-recon") || strings.Contains(lanRecon, "js-api-recon") {
		t.Fatalf("LAN single-IP recon must not recommend external domain/SPA skills: %s", lanRecon)
	}
	if !strings.Contains(lanRecon, "windows-ad-postex") {
		t.Fatalf("LAN host recon should recommend internal skills: %s", lanRecon)
	}

	// 3. External enterprise recon still recommends tbhm-recon / js-api-recon.
	extRecon := SkillGuideForIntent(payload(t, map[string]any{
		"summary":    "对目标企业做子域收集、ASN 发现与前端 SPA JS 路由测绘",
		"chain_tags": []string{"recon"},
	}))
	if !strings.Contains(extRecon, "tbhm-recon") || !strings.Contains(extRecon, "js-api-recon") {
		t.Fatalf("external recon must keep tbhm-recon/js-api-recon: %s", extRecon)
	}

	// 4. Multi-tag ["ad","pivot"] renders hints for BOTH categories, not only cats[0].
	multi := SkillGuideForIntent(payload(t, map[string]any{
		"summary":    "经 SOCKS5 隧道打 XDORG 域控 Zerologon",
		"chain_tags": []string{"ad", "pivot"},
	}))
	if !strings.Contains(multi, "[ad]") || !strings.Contains(multi, "[pivot]") || !strings.Contains(multi, "multi-hop-pivoting") || !strings.Contains(multi, "windows-ad-postex") {
		t.Fatalf("multi-tag intent must surface both ad and pivot skills: %s", multi)
	}

	// 5. Priority skills still honor visibility resolver.
	prev := SkillCatalogResolver
	t.Cleanup(func() { SkillCatalogResolver = prev })
	SkillCatalogResolver = func(string) (map[string]bool, map[string]string) {
		return map[string]bool{"multi-hop-pivoting": true}, map[string]string{"multi-hop-pivoting": "多跳代理"}
	}
	filtered := SkillGuideForIntent(payload(t, map[string]any{
		"summary":    "经 SOCKS5 跳板打 WebLogic 7001",
		"chain_tags": []string{"pivot"},
	}))
	if strings.Contains(filtered, "weblogic-java-rce") || !strings.Contains(filtered, "multi-hop-pivoting") {
		t.Fatalf("visibility resolver must filter disabled priority skills: %s", filtered)
	}
}
