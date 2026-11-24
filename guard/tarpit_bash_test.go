package guard

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func bashInput(cmd string) []byte {
	b, _ := json.Marshal(map[string]string{"command": cmd})
	return b
}

func TestGuardTarpitCountsBashFetchersNotOtherCommands(t *testing.T) {
	g := New()
	var hints []string
	g.SetTarpit(TarpitConfig{
		Budget: func() int { return 2 },
		Hint:   func(host string, count int) { hints = append(hints, host) },
	})
	pre := func(name string, input []byte) bool {
		blocked, _, _ := g.Hooks().PreToolUse(context.Background(), name, input)
		return blocked
	}

	hostURL := "https://maze.example/a"
	// 非抓取类 Bash 不计预算。
	if pre("Bash", bashInput("echo "+hostURL)) {
		t.Fatal("echo must not be blocked")
	}
	if pre("Bash", bashInput("nmap -p 80 maze.example")) {
		t.Fatal("nmap must not be blocked")
	}
	if len(hints) != 0 {
		t.Fatalf("non-fetch Bash must not count, hints=%v", hints)
	}

	// curl/ffuf/katana/httpx 计入同一 host 预算(与 WebFetch 共用)。
	if pre("Bash", bashInput("curl -s "+hostURL)) || pre("Bash", bashInput("ffuf -u https://maze.example/FUZZ")) {
		t.Fatal("in-budget fetch Bash must not be blocked")
	}
	if len(hints) != 0 {
		t.Fatalf("no hint before budget exceeded, got %v", hints)
	}
	// 第 3 次(httpx)超预算: hint + warn 放行,不 block。
	if pre("Bash", bashInput("httpx -u https://maze.example")) {
		t.Fatal("tarpit trip should warn-allow, not block")
	}
	if len(hints) != 1 || hints[0] != "maze.example" {
		t.Fatalf("expected one hint for maze.example, got %v", hints)
	}
	// katana 再抓: 仍放行,不再重复 hint。
	if pre("Bash", bashInput("katana -u https://maze.example")) {
		t.Fatal("post-trip katana must warn-allow, not block")
	}
	if len(hints) != 1 {
		t.Fatalf("hint must fire only once per host, got %v", hints)
	}

	// 既有 WebFetch 计数仍在,且与 Bash 共享同一 host 计数(已熔断,只再记 warn)。
	fetch, _ := json.Marshal(map[string]string{"url": "https://maze.example/z"})
	if pre("WebFetch", fetch) {
		t.Fatal("WebFetch after trip must still be allowed")
	}

	// 无法解析 host 的 curl 跳过计数,不误伤其他 host。
	if pre("Bash", bashInput("curl")) {
		t.Fatal("curl without host must skip count, not block")
	}

	var trip, after int
	for _, a := range g.Audit() {
		if strings.Contains(a.Reason, "疑似 tarpit 迷宫") {
			trip++
		}
		if strings.Contains(a.Reason, "tarpit 熔断后仍抓取") {
			after++
		}
	}
	if trip != 1 {
		t.Fatalf("want 1 trip audit, got %d", trip)
	}
	if after < 2 { // katana + WebFetch at least
		t.Fatalf("want post-trip warns, got %d", after)
	}
}

func TestBashFetchHostsIgnoresEchoAndNmap(t *testing.T) {
	if got := bashFetchHosts("echo https://maze.example/a"); len(got) != 0 {
		t.Fatalf("echo must not count, got %v", got)
	}
	if got := bashFetchHosts("nmap -p 80 maze.example"); len(got) != 0 {
		t.Fatalf("nmap must not count, got %v", got)
	}
	if got := bashFetchHosts("curl https://maze.example/a"); len(got) != 1 || got[0] != "maze.example" {
		t.Fatalf("curl url, got %v", got)
	}
	if got := bashFetchHosts("/usr/bin/curl --url=https://other.example/"); len(got) != 1 || got[0] != "other.example" {
		t.Fatalf("absolute curl, got %v", got)
	}
}

func TestGuardTarpitSkipsMutationsCapsStaticPollingAndSplitsPorts(t *testing.T) {
	g := New()
	var hints []string
	g.SetTarpit(TarpitConfig{
		Budget: func() int { return 4 },
		Hint:   func(host string, count int) { hints = append(hints, host) },
	})
	pre := func(name string, input []byte) bool {
		blocked, _, _ := g.Hooks().PreToolUse(context.Background(), name, input)
		return blocked
	}

	// 1. State-changing curl calls (POST/-d) do not count toward tarpit.
	for i := 0; i < 10; i++ {
		if pre("Bash", bashInput(`curl -s -X POST "https://bench.example/openapi/v1/challenges/start?unique_code=c-03"`)) {
			t.Fatal("POST curl must not be blocked")
		}
		if pre("Bash", bashInput(`curl -s -d '{"flag":"x"}' "https://bench.example/openapi/v1/challenges/submit"`)) {
			t.Fatal("-d curl must not be blocked")
		}
	}
	// 2. Polling the identical static GET URL 50 times caps at 3 (< budget 4).
	for i := 0; i < 50; i++ {
		if pre("Bash", bashInput(`curl -s "https://bench.example/openapi/v1/challenges"`)) {
			t.Fatal("static GET polling must not be blocked")
		}
	}
	if len(hints) != 0 {
		t.Fatalf("POST + static GET polling must not trip tarpit, got hints=%v", hints)
	}

	// 3. Non-default ports on the same IP are tracked separately.
	for i := 0; i < 4; i++ {
		pre("Bash", bashInput("curl -s http://10.0.164.138:8080/p"+string(rune('a'+i))))
		pre("Bash", bashInput("curl -s http://10.0.164.138:9011/p"+string(rune('a'+i))))
	}
	if len(hints) != 0 {
		t.Fatalf("4 distinct fetches per port (<= budget 4) must not trip, got hints=%v", hints)
	}
	// 5th distinct path on :8080 trips only 10.0.164.138:8080.
	pre("Bash", bashInput("curl -s http://10.0.164.138:8080/pe"))
	if len(hints) != 1 || hints[0] != "10.0.164.138:8080" {
		t.Fatalf("expected tarpit hint on 10.0.164.138:8080 only, got %v", hints)
	}
}

func TestGuardTarpitIsolatedByScopeKey(t *testing.T) {
	g := New()
	var hints []string
	g.SetTarpit(TarpitConfig{
		Budget: func() int { return 3 },
		Hint:   func(host string, count int) { hints = append(hints, host) },
	})
	ctx1 := WithScopeKey(context.Background(), "intent:101")
	ctx2 := WithScopeKey(context.Background(), "intent:102")

	// Two intents reuse the same recycled benchmark IP on :80, each doing 3 fetches (== budget 3).
	for i := 0; i < 3; i++ {
		if b, _, _ := g.Hooks().PreToolUse(ctx1, "Bash", bashInput("curl -s http://10.0.164.136/p"+string(rune('a'+i)))); b {
			t.Fatal("ctx1 probe blocked unexpectedly")
		}
		if b, _, _ := g.Hooks().PreToolUse(ctx2, "Bash", bashInput("curl -s http://10.0.164.136/q"+string(rune('a'+i)))); b {
			t.Fatal("ctx2 probe blocked unexpectedly")
		}
	}
	if len(hints) != 0 {
		t.Fatalf("scoped intents must not accumulate tarpit across recycled :80 IP, got hints=%v", hints)
	}

	// Exceeding budget within a single intent trips once and reports clean hostname.
	g.Hooks().PreToolUse(ctx1, "Bash", bashInput("curl -s http://10.0.164.136/overflow"))
	if len(hints) != 1 || hints[0] != "10.0.164.136" {
		t.Fatalf("expected single clean host hint on scope budget overflow, got %v", hints)
	}
}
