package traffic

import (
	"sort"
	"sync"
	"testing"
	"time"
)

func TestPacerConcurrentReservationsStaySpaced(t *testing.T) {
	const requests = 64
	base := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	interval := 25 * time.Millisecond
	p := newPacerInterval(interval, 1)
	p.now = func() time.Time { return base }
	start := make(chan struct{})
	slots := make(chan time.Time, requests)
	var wg sync.WaitGroup
	for range requests {
		wg.Go(func() { <-start; slots <- p.reserve("same.example") })
	}
	close(start)
	wg.Wait()
	close(slots)
	var ordered []time.Time
	for slot := range slots {
		ordered = append(ordered, slot)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Before(ordered[j]) })
	for i, slot := range ordered {
		want := base.Add(time.Duration(i) * interval)
		if !slot.Equal(want) {
			t.Fatalf("concurrent reservation %d: %v want %v", i, slot, want)
		}
	}
}

func TestPacerReserve(t *testing.T) {
	base := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	interval := 100 * time.Millisecond
	p := newPacerInterval(interval, 3)
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

func TestNewPacerInterval(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		if p := newPacerInterval(interval, 3); p != nil {
			t.Fatalf("interval %v: got non-nil pacer", interval)
		}
	}
	for _, burst := range []int{0, -1, 1} {
		p := newPacerInterval(100*time.Millisecond, burst)
		if p.burst != 0 {
			t.Fatalf("burst %d: tolerance = %v, want 0", burst, p.burst)
		}
	}
}

func TestNewPacer(t *testing.T) {
	p := NewPacer(10, 0)
	if p == nil || p.interval != 100*time.Millisecond {
		t.Fatalf("NewPacer(10, 0) = %v, want interval 100ms", p)
	}
	for _, rps := range []float64{0, -1} {
		if p := NewPacer(rps, 0); p != nil {
			t.Fatalf("NewPacer(%v, 0) = %v, want nil", rps, p)
		}
	}
}

func TestSharedPacer(t *testing.T) {
	base := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	p := NewPacer(10, 1)
	p.now = func() time.Time { return base }
	var global, taskA, taskB Traffic
	for i, tr := range []*Traffic{&global, &taskA, &taskB} {
		tr.SetHostPacer(p)
		want := base.Add(time.Duration(i) * 100 * time.Millisecond)
		if got := tr.pace.Load().reserve("example.com"); !got.Equal(want) {
			t.Fatalf("proxy %d reservation = %v, want %v", i, got, want)
		}
	}
	taskA.SetHostPacer(nil)
	if taskA.pace.Load() != nil || global.pace.Load() != p || taskB.pace.Load() != p {
		t.Fatal("clearing one proxy changed another proxy's pacer")
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
