package traffic

import (
	"testing"
	"time"
)

func TestPacerReserve(t *testing.T) {
	base := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	interval := 100 * time.Millisecond
	p := newPacer(interval, 3)
	p.now = func() time.Time { return base }
	for i := 0; i < 3; i++ {
		if got := p.reserve("a"); !got.Equal(base) {
			t.Fatalf("burst request %d: got %v, want %v", i+1, got, base)
		}
	}
	for i := 1; i <= 5; i++ {
		want := base.Add(time.Duration(i) * interval)
		if got := p.reserve("a"); !got.Equal(want) {
			t.Fatalf("post-burst request %d: got %v, want %v", i, got, want)
		}
	}
	if got := p.reserve("b"); !got.Equal(base) {
		t.Fatalf("independent host: got %v, want %v", got, base)
	}
	idle := base.Add(time.Hour)
	p.now = func() time.Time { return idle }
	if got := p.reserve("a"); !got.Equal(idle) {
		t.Fatalf("idle refill: got %v, want %v", got, idle)
	}
}

func TestNewPacer(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		if p := newPacer(interval, 3); p != nil {
			t.Fatalf("interval %v: got non-nil pacer", interval)
		}
	}
	for _, burst := range []int{0, -1, 1} {
		p := newPacer(100*time.Millisecond, burst)
		if p.burst != 0 {
			t.Fatalf("burst %d: tolerance = %v, want 0", burst, p.burst)
		}
	}
}

func TestIsLoopback(t *testing.T) {
	for _, tt := range []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"example.com", false},
		{"10.0.0.5", false},
		{"", false},
	} {
		t.Run(tt.host, func(t *testing.T) {
			if got := isLoopback(tt.host); got != tt.want {
				t.Fatalf("isLoopback(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}
