package agent

import (
	"strings"
	"testing"
)

func TestShellHintCatalogKeys(t *testing.T) {
	want := []string{
		"ffuf", "feroxbuster", "gobuster",
		"sqlmap", "hydra", "nmap",
		"nuclei", "whatweb", "commix",
		"hashcat", "john", "katana", "httpx", "jq",
		"nxc",
		"impacket-secretsdump", "impacket-psexec", "impacket-wmiexec",
		"impacket-smbclient", "impacket-GetUserSPNs",
	}
	seeds := ShellHintSeeds()
	if len(seeds) != len(want) {
		t.Fatalf("catalog len=%d, want %d", len(seeds), len(want))
	}
	seen := map[string]bool{}
	for i, s := range seeds {
		if s.Key != want[i] {
			t.Errorf("seeds[%d]=%s, want %s", i, s.Key, want[i])
		}
		if s.Desc == "" {
			t.Errorf("%s: empty description", s.Key)
		}
		if seen[s.Key] {
			t.Errorf("duplicate key %s", s.Key)
		}
		seen[s.Key] = true
		if strings.Contains(s.Desc, "Kali") || strings.Contains(s.Desc, "kali") {
			t.Errorf("%s description mentions Kali: %s", s.Key, s.Desc)
		}
	}
	agents := ShellHintDefaultAgents()
	if len(agents) != 2 || agents[0] != "worker" || agents[1] != "pentest" {
		t.Fatalf("default agents=%v, want worker+pentest", agents)
	}
	if _, ok := ShellHintByKey("nmap"); !ok {
		t.Fatal("ShellHintByKey(nmap) missing")
	}
	if _, ok := ShellHintByKey("secretsdump.py"); ok {
		t.Fatal("alias secretsdump.py must not be a catalog key")
	}

	// nxc / impacket: capability + when, not harvest or movement steps.
	for _, key := range []string{"nxc", "impacket-secretsdump", "impacket-psexec", "impacket-wmiexec", "impacket-smbclient", "impacket-GetUserSPNs"} {
		s, ok := ShellHintByKey(key)
		if !ok {
			t.Fatalf("missing %s", key)
		}
		if !strings.Contains(s.Desc, "已授权内网按需") && !strings.Contains(s.Desc, "已授权") {
			t.Errorf("%s should state authorized on-demand use: %s", key, s.Desc)
		}
		if key == "nxc" && !strings.Contains(s.Desc, "不是默认必装") {
			t.Errorf("%s should say it is not a required default install: %s", key, s.Desc)
		}
		for _, banned := range []string{"横向移动", "收割步骤", "下一步先", "然后执行", "先 dump", "再横向"} {
			if strings.Contains(s.Desc, banned) {
				t.Errorf("%s looks like a harvest/movement procedure (%s): %s", key, banned, s.Desc)
			}
		}
	}
}

func TestWorkerSystemShellCLIRulesAreCodeTail(t *testing.T) {
	t.Cleanup(func() { PromptOverride = nil })
	PromptOverride = nil

	off := workerSystem("", "", "/data", "/data", false, DefaultFootprint())
	if !strings.Contains(off, "CLI 优先") {
		t.Fatalf("always-on CLI discipline missing:\n%s", off)
	}
	if !strings.Contains(off, "Bash 说明里已列出") {
		t.Fatalf("CLI discipline must point at Bash-listed tools:\n%s", off)
	}
	if strings.Contains(off, "打回攻击机") || strings.Contains(off, "平台侧") || strings.Contains(off, "对方壳里手写扫描器") {
		t.Fatalf("intranet foothold sentence must be absent when not in intranet phase:\n%s", off)
	}
	if strings.Contains(off, "Kali") || strings.Contains(off, "打回 Kali") {
		t.Fatalf("product copy must not say Kali:\n%s", off)
	}
	for _, named := range []string{"nmap", "sqlmap", "ffuf", "hydra", "nuclei"} {
		if strings.Contains(off, named) {
			t.Fatalf("CLI discipline must not hard-code %s:\n%s", named, off)
		}
	}

	on := workerSystem("", "", "/data", "/data", true, DefaultFootprint())
	if !strings.Contains(on, "CLI 优先") || !strings.Contains(on, "Bash 说明里已列出") {
		t.Fatalf("CLI discipline must remain during intranet phase:\n%s", on)
	}
	if !strings.Contains(on, "打回攻击机/平台侧") || !strings.Contains(on, "不要在对方壳里手写扫描器") {
		t.Fatalf("intranet phase should add foothold scan-back sentence:\n%s", on)
	}
	if strings.Contains(on, "Kali") || strings.Contains(on, "打回 Kali") {
		t.Fatalf("product copy must not say Kali:\n%s", on)
	}

	// DB body override cannot drop the code tail.
	PromptOverride = func(k string) (string, bool) {
		if k == "worker" {
			return "仅正文", true
		}
		return "", false
	}
	overridden := workerSystem("", "", "/data", "/data", false, DefaultFootprint())
	if !strings.HasPrefix(overridden, "仅正文") {
		t.Fatalf("worker body should honor override: %q", overridden)
	}
	if !strings.Contains(overridden, "CLI 优先") {
		t.Fatalf("DB body must not be able to drop CLI tail: %q", overridden)
	}

	// Path A: do not plant a fake agent key in BuiltinPromptSeeds.
	for key := range BuiltinPromptSeeds() {
		if key == "worker.cli" || key == "worker.intranet" || strings.Contains(key, ".") {
			t.Fatalf("BuiltinPromptSeeds must not contain variant/fake key %q", key)
		}
	}
}
