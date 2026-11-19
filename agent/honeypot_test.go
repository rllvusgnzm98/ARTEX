package agent

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/honeydetect"
)

func TestHoneypotDispositionContract(t *testing.T) {
	// 误报优先于漏报:单信号不封锁,双信号才封锁方向。
	cases := []struct {
		static, behavioral bool
		want               string
	}{
		{false, false, HoneypotDispositionNone},
		{true, false, HoneypotDispositionDegrade},
		{false, true, HoneypotDispositionDegrade},
		{true, true, HoneypotDispositionBlockDirection},
	}
	for _, c := range cases {
		if got := HoneypotDispositionFor(c.static, c.behavioral); got != c.want {
			t.Errorf("HoneypotDispositionFor(%v,%v)=%q want %q", c.static, c.behavioral, got, c.want)
		}
	}
}

func TestPlannerHoneypotRulesAreCodeTail(t *testing.T) {
	t.Cleanup(func() { PromptOverride = nil })
	PromptOverride = func(k string) (string, bool) { return "用户编辑正文", true }
	got := plannerSystem("核验", "/data", "/data")
	if !strings.HasPrefix(got, "用户编辑正文") {
		t.Fatalf("planner 正文应仍被尊重: %q", got)
	}
	for _, needle := range []string{
		"蜜罐处置纪律",
		"仅凭单信号不得封锁方向",
		"双信号命中",
		"停止在该方向派意图",
		"不投递工具/载荷、不爆破、不利用",
	} {
		if !strings.Contains(got, needle) {
			t.Fatalf("planner 代码固定尾缺少 %q: %q", needle, got)
		}
	}
}

func TestHoneypotConfidenceMapping(t *testing.T) {
	cases := map[float64]string{0.99: "high", 0.9: "high", 0.85: "medium", 0.6: "medium"}
	for score, want := range cases {
		if got := honeypotConfidence(score); got != want {
			t.Errorf("honeypotConfidence(%v)=%q want %q", score, got, want)
		}
	}
}

func TestURLPort(t *testing.T) {
	cases := map[string]int{
		"http://a.example":        80,
		"https://a.example/path":  443,
		"http://a.example:8080/x": 8080,
		"not a url ::":            0,
	}
	for raw, want := range cases {
		if got := urlPort(raw); got != want {
			t.Errorf("urlPort(%q)=%d want %d", raw, got, want)
		}
	}
}

func TestEvaluateHoneypotNilStoresNoPanic(t *testing.T) {
	ts := &ToolSet{}
	ts.evaluateHoneypot(0, honeydetect.ServiceView{Port: 22})
	ts.evaluateHoneypot(1, honeydetect.ServiceView{Port: 22, Banner: "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"})
}
