package guard

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestHoneypotGateBlockDegradeAndNil(t *testing.T) {
	fetch := func(raw string) []byte {
		b, _ := json.Marshal(map[string]string{"url": raw})
		return b
	}
	pre := func(g *Guard, name string, input []byte) (bool, string) {
		t.Helper()
		blocked, msg, _ := g.Hooks().PreToolUse(context.Background(), name, input)
		return blocked, msg
	}

	t.Run("block-direction", func(t *testing.T) {
		g := New()
		g.SetHoneypot(HoneypotConfig{Check: func(host string) (string, string) {
			if host == "honey.example" {
				return "block-direction", "确认蜜罐（双信号），停止该方向"
			}
			return "", ""
		}})
		blocked, msg := pre(g, "WebFetch", fetch("http://honey.example/login"))
		if !blocked {
			t.Fatal("block-direction must hard-block")
		}
		if !strings.Contains(msg, "非目标防御") || !strings.Contains(msg, "平台") || !strings.Contains(msg, "双信号") {
			t.Fatalf("block message should name platform policy, got %q", msg)
		}
		saw := false
		for _, a := range g.Audit() {
			if a.Action == "block" && strings.Contains(a.Reason, "双信号") {
				saw = true
			}
		}
		if !saw {
			t.Fatalf("audit missing block: %+v", g.Audit())
		}
	})

	t.Run("degrade allows and records", func(t *testing.T) {
		g := New()
		g.SetHoneypot(HoneypotConfig{Check: func(host string) (string, string) {
			if host == "maybe.example" {
				return "degrade", "单信号降级告警放行"
			}
			return "none", "should-not-record"
		}})
		blocked, _ := pre(g, "Bash", bashInput("curl -s http://maybe.example/index"))
		if blocked {
			t.Fatal("degrade must warn-allow, not block")
		}
		saw := false
		for _, a := range g.Audit() {
			if strings.Contains(a.Reason, "单信号降级告警放行") && a.Action == "allow" {
				saw = true
			}
			if strings.Contains(a.Reason, "should-not-record") {
				t.Fatal("unknown/none disposition must not be recorded")
			}
		}
		if !saw {
			t.Fatalf("degrade reason missing from audit: %+v", g.Audit())
		}
	})

	t.Run("nil check is unchanged", func(t *testing.T) {
		input := fetch("http://honey.example/login")
		plain := New()
		wired := New()
		wired.SetHoneypot(HoneypotConfig{})
		b1, m1 := pre(plain, "WebFetch", input)
		b2, m2 := pre(wired, "WebFetch", input)
		if b1 || b2 || m1 != m2 {
			t.Fatalf("nil Check changed the gate: plain=(%v,%q) wired=(%v,%q)", b1, m1, b2, m2)
		}
		if len(plain.Audit()) != len(wired.Audit()) {
			t.Fatalf("nil Check changed audit len: plain=%d wired=%d", len(plain.Audit()), len(wired.Audit()))
		}
		for _, a := range wired.Audit() {
			if strings.Contains(a.Reason, "蜜罐") {
				t.Fatalf("nil Check wrote a honeypot audit: %+v", a)
			}
		}
	})
}
