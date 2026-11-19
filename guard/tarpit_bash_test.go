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
