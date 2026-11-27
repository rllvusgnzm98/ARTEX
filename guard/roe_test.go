package guard

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
)

// RoE 集成测试(无 interceptor 的可测部分):strict+Out 无审批通道 → 硬拦;
// warn → 放行但写审计;In / Unknown / off / 无目标 / 无 taskID → 放行。

func roeGuard(mode string, rules []ScopeRule) *Guard {
	g := New()
	g.SetRoE(RoEConfig{
		Mode:     func() string { return mode },
		Scope:    func(taskID int64) ([]ScopeRule, error) { return rules, nil },
		TaskIDOf: func(ctx context.Context) int64 { return 42 },
	})
	return g
}

func bashBlocked(t *testing.T, g *Guard, cmd string) (bool, string) {
	t.Helper()
	input, _ := json.Marshal(map[string]string{"command": cmd})
	blocked, msg, _ := g.Hooks().PreToolUse(context.Background(), "Bash", input)
	return blocked, msg
}

func TestRoEStrictBlocksOutOfScope(t *testing.T) {
	g := roeGuard("strict", []ScopeRule{{Kind: "domain", Value: "target.com"}})
	blocked, msg := bashBlocked(t, g, `curl https://evil.com/`)
	if !blocked {
		t.Fatal("strict 模式下范围外目标应被拦截")
	}
	if !strings.Contains(msg, "evil.com") || !strings.Contains(msg, "roe_enforcement") {
		t.Errorf("拦截消息应写明 host 与关闭/降级方式, got: %s", msg)
	}
}

func TestRoEStrictAllowsInScope(t *testing.T) {
	g := roeGuard("strict", []ScopeRule{{Kind: "domain", Value: "target.com"}})
	for _, cmd := range []string{
		`curl https://api.target.com/`,
		`nmap 127.0.0.1`,           // 本机操作放行
		`ls -la`,                   // 无目标
		`curl https://target.com/`, //
	} {
		if blocked, _ := bashBlocked(t, g, cmd); blocked {
			t.Errorf("strict 模式下 %q 不应被拦截", cmd)
		}
	}
}

func TestRoEUnknownScopeAllows(t *testing.T) {
	// 未登记范围 / 空范围 → Unknown → 放行,warn 与 strict 都是既定语义。
	for _, mode := range []string{"strict", "warn"} {
		g := roeGuard(mode, nil)
		if blocked, _ := bashBlocked(t, g, `curl https://anything.com/`); blocked {
			t.Errorf("mode %q 未登记范围不应拦截", mode)
		}
		for _, e := range g.Audit() {
			if strings.Contains(e.Reason, "读取失败") {
				t.Errorf("mode %q 未登记范围的审计不应写成读失败: %+v", mode, e)
			}
		}
	}
}

func TestRoEWarnAllowsButAudits(t *testing.T) {
	g := roeGuard("warn", []ScopeRule{{Kind: "cidr", Value: "10.0.0.0/8"}})
	if blocked, _ := bashBlocked(t, g, `nmap 172.16.0.5`); blocked {
		t.Fatal("warn 模式应放行")
	}
	var found bool
	for _, e := range g.Audit() {
		if e.Action == "allow" && strings.Contains(e.Reason, "RoE") && strings.Contains(e.Reason, "172.16.0.5") {
			found = true
		}
	}
	if !found {
		t.Error("warn 放行应写 guard 审计(注明 RoE 与 host)")
	}
}

func TestRoEOffDisables(t *testing.T) {
	g := roeGuard("off", []ScopeRule{{Kind: "domain", Value: "target.com"}})
	if blocked, _ := bashBlocked(t, g, `curl https://evil.com/`); blocked {
		t.Error("off 模式不应拦截")
	}
}

func TestRoENoTaskIDAllows(t *testing.T) {
	g := roeGuard("strict", []ScopeRule{{Kind: "domain", Value: "target.com"}})
	g.SetRoE(RoEConfig{
		Mode:     func() string { return "strict" },
		Scope:    func(int64) ([]ScopeRule, error) { return []ScopeRule{{Kind: "domain", Value: "target.com"}}, nil },
		TaskIDOf: func(context.Context) int64 { return 0 }, // chat 等非任务运行
	})
	if blocked, _ := bashBlocked(t, g, `curl https://evil.com/`); blocked {
		t.Error("无 taskID 应放行")
	}
}

func TestRoEWebFetch(t *testing.T) {
	g := roeGuard("strict", []ScopeRule{{Kind: "domain", Value: "target.com"}})
	input, _ := json.Marshal(map[string]string{"url": "https://evil.com/x"})
	blocked, _, _ := g.Hooks().PreToolUse(context.Background(), "WebFetch", input)
	if !blocked {
		t.Error("WebFetch 的 URL host 同样受 RoE 检查")
	}
}

func TestRoEEmptyAndUnknownModeIsWarn(t *testing.T) {
	// 产品默认、空值、未知值一律回落 warn:范围外放行但写审计,而不是改成 strict。
	rules := []ScopeRule{{Kind: "cidr", Value: "10.0.0.0/8"}}
	for _, mode := range []string{"", "  ", "unknown", "WARN", "warn"} {
		g := roeGuard(mode, rules)
		blocked, _ := bashBlocked(t, g, `nmap 172.16.0.5`)
		if blocked {
			t.Fatalf("mode %q 应回落/保持 warn 并放行,却被拦截", mode)
		}
		var found bool
		for _, e := range g.Audit() {
			if e.Action == "allow" && strings.Contains(e.Reason, "RoE") && strings.Contains(e.Reason, "172.16.0.5") {
				found = true
			}
		}
		if !found {
			t.Fatalf("mode %q 应写 RoE 审计, got %+v", mode, g.Audit())
		}
	}
}

func roeGuardScopeErr(mode string, err error) *Guard {
	g := New()
	g.SetRoE(RoEConfig{
		Mode:     func() string { return mode },
		Scope:    func(int64) ([]ScopeRule, error) { return nil, err },
		TaskIDOf: func(context.Context) int64 { return 42 },
	})
	return g
}

func TestRoEScopeLoadErrorStrictDoesNotFailOpen(t *testing.T) {
	g := roeGuardScopeErr("strict", errors.New("scope store unavailable"))
	blocked, msg := bashBlocked(t, g, `curl https://anything.com/`)
	if !blocked {
		t.Fatal("ListTaskScope 读失败在 strict 下不得当成空范围放行")
	}
	if !strings.Contains(msg, "读取失败") || !strings.Contains(msg, "非未登记范围") {
		t.Errorf("拦截消息应标明是读失败而非未登记, got: %s", msg)
	}
	var allows, blocks int
	for _, e := range g.Audit() {
		if e.Action == "allow" && e.Reason == "" {
			t.Errorf("strict 拦下时不得先留下空 reason 的 allow 行: %+v", e)
		}
		if e.Action == "allow" {
			allows++
		}
		if e.Action == "block" && strings.Contains(e.Reason, "读取失败") {
			blocks++
		}
	}
	if allows != 0 {
		t.Errorf("strict 读失败应只有 block, 不应有 allow, got allows=%d audit=%+v", allows, g.Audit())
	}
	if blocks != 1 {
		t.Errorf("strict 读失败应记一条读失败 block, got %d audit=%+v", blocks, g.Audit())
	}
}

func TestRoEScopeLoadErrorWarnAllowsWithDistinctAudit(t *testing.T) {
	g := roeGuardScopeErr("warn", errors.New("scope store unavailable"))
	if blocked, _ := bashBlocked(t, g, `curl https://anything.com/`); blocked {
		t.Fatal("ListTaskScope 读失败在 warn 下应放行")
	}
	var found bool
	for _, e := range g.Audit() {
		if e.Action == "allow" && strings.Contains(e.Reason, "读取失败") && strings.Contains(e.Reason, "非未登记范围") {
			found = true
		}
	}
	if !found {
		t.Fatalf("warn 下放行须留下可与未登记区分的读失败审计, got %+v", g.Audit())
	}

	// 对照:同一模式下未登记范围不得出现「读取失败」字样。
	empty := roeGuard("warn", nil)
	if blocked, _ := bashBlocked(t, empty, `curl https://anything.com/`); blocked {
		t.Fatal("未登记范围在 warn 下应放行")
	}
	for _, e := range empty.Audit() {
		if strings.Contains(e.Reason, "读取失败") {
			t.Fatalf("未登记范围审计被写成读失败: %+v", e)
		}
	}
}

func TestPreToolUseAllowOnlyAfterAllGates(t *testing.T) {
	// strict 范围外拦截时,不得先留下空 reason 的 allow。
	g := roeGuard("strict", []ScopeRule{{Kind: "domain", Value: "target.com"}})
	if blocked, _ := bashBlocked(t, g, `curl https://evil.com/`); !blocked {
		t.Fatal("strict 范围外应拦截")
	}
	for _, e := range g.Audit() {
		if e.Action == "allow" && e.Reason == "" {
			t.Fatalf("后面闸门拦住时不得先留下空 reason 的 allow 行: %+v", e)
		}
		if e.Action == "allow" {
			t.Fatalf("strict 拦下不应有 allow 行: %+v", e)
		}
	}

	// 全部闸门通过后才记一条空 reason 的 allow。
	ok := roeGuard("strict", []ScopeRule{{Kind: "domain", Value: "target.com"}})
	if blocked, _ := bashBlocked(t, ok, `curl https://target.com/`); blocked {
		t.Fatal("范围内目标应放行")
	}
	var emptyAllow int
	for _, e := range ok.Audit() {
		if e.Action == "allow" && e.Reason == "" {
			emptyAllow++
		}
	}
	if emptyAllow != 1 {
		t.Fatalf("全部闸门通过后应恰好一条空 reason allow, got %+v", ok.Audit())
	}
}

func TestRoEUsesExtractedShellHintHosts(t *testing.T) {
	// 新 CLI 抽出的 host 仍走既有 warn/strict 语义;不改 roeAsk/一键放行路径。
	strict := roeGuard("strict", []ScopeRule{{Kind: "domain", Value: "target.com"}})
	for _, cmd := range []string{
		`ffuf -u https://evil.com/FUZZ -w /tmp/words.txt`,
		`gobuster dns -d evil.com`,
		`nuclei -u evil.com`,
		`nxc smb 10.0.0.7`,
		`impacket-psexec user@evil.com`,
	} {
		if blocked, _ := bashBlocked(t, strict, cmd); !blocked {
			t.Errorf("strict 应对抽出的范围外 host 拦截: %q", cmd)
		}
	}
	if blocked, _ := bashBlocked(t, strict, `ffuf -u https://api.target.com/FUZZ`); blocked {
		t.Error("strict 下范围内目标不应拦截")
	}
	// CIDR 字面量仍不提取 → 无目标 → 不拦截(既有保守语义)。
	if blocked, _ := bashBlocked(t, strict, `nxc smb 192.168.1.0/24`); blocked {
		t.Error("CIDR 字面量不提取时不应按范围外拦截")
	}

	warn := roeGuard("warn", []ScopeRule{{Kind: "domain", Value: "target.com"}})
	if blocked, _ := bashBlocked(t, warn, `katana -u https://evil.com`); blocked {
		t.Fatal("warn 模式应放行")
	}
	var found bool
	for _, e := range warn.Audit() {
		if e.Action == "allow" && strings.Contains(e.Reason, "RoE") && strings.Contains(e.Reason, "evil.com") {
			found = true
		}
	}
	if !found {
		t.Fatalf("warn 放行应写 RoE 审计(含抽出的 host), got %+v", warn.Audit())
	}
}

func TestRoELocalInterfaceAndCallbackAutoExemption(t *testing.T) {
	orig := interfaceAddrsFn
	t.Cleanup(func() { interfaceAddrsFn = orig })
	interfaceAddrsFn = func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
			&net.IPNet{IP: net.ParseIP("10.8.0.5"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("192.168.111.25"), Mask: net.CIDRMask(24, 32)},
		}, nil
	}
	t.Setenv("ARTEX_CALLBACK_ADDR", "203.0.113.42:4444")

	rules := []ScopeRule{{Kind: "ip", Value: "192.168.111.20"}}
	strict := roeGuard("strict", rules)
	for _, cmd := range []string{
		`curl http://10.8.0.5:8000/shell.sh`,
		`curl http://192.168.111.25:8080/loot`,
		`nc 203.0.113.42 4444`,
	} {
		if blocked, msg := bashBlocked(t, strict, cmd); blocked {
			t.Errorf("local/VPN/callback host should be exempted in strict mode (%q): %s", cmd, msg)
		}
	}
	// Non-local out-of-scope IP must still be blocked in strict mode.
	if blocked, _ := bashBlocked(t, strict, `curl http://10.8.0.99/`); !blocked {
		t.Error("non-local out-of-scope IP 10.8.0.99 must still be blocked in strict mode")
	}

	// Warn mode must not spam RoE audit warnings for local NIC / callback IPs.
	warn := roeGuard("warn", rules)
	if blocked, _ := bashBlocked(t, warn, `curl http://192.168.111.25:8000/payload`); blocked {
		t.Fatal("warn mode should allow")
	}
	for _, e := range warn.Audit() {
		if strings.Contains(e.Reason, "RoE") {
			t.Errorf("local NIC IP should not produce RoE warning audit: %+v", e)
		}
	}

	// Explicit exclude_ip must still override local NIC exemption.
	exclStrict := roeGuard("strict", []ScopeRule{
		{Kind: "ip", Value: "192.168.111.20"},
		{Kind: "exclude_ip", Value: "10.8.0.5"},
	})
	if blocked, _ := bashBlocked(t, exclStrict, `curl http://10.8.0.5/`); !blocked {
		t.Error("explicit exclude_ip must override local NIC auto-exemption")
	}
}
