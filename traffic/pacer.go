package traffic

import (
	"context"
	"net"
	"sync"
	"time"
)

// pacerMaxHosts bounds the per-host schedule map so the shared global proxy
// cannot grow it without limit; above it, entries already in the past are pruned.
const pacerMaxHosts = 4096

// pacer is a polite per-host request limiter: it delays (never drops) requests so
// that, per target host, sustained throughput stays at interval^-1 req/s while
// short bursts up to `burst` are let through immediately. It is a GCRA (generic
// cell rate algorithm) keeping one theoretical-arrival-time (tat) per host.
type pacer struct {
	interval time.Duration // minimum sustained spacing between requests to one host
	burst    time.Duration // burst tolerance = (burst-1)*interval
	now      func() time.Time
	mu       sync.Mutex
	tat      map[string]time.Time
}

// newPacer returns a pacer spacing requests `interval` apart with a bucket of
// `burst` (burst<1 is treated as 1). interval<=0 returns nil (pacing disabled).
func newPacer(interval time.Duration, burst int) *pacer {
	if interval <= 0 {
		return nil
	}
	if burst < 1 {
		burst = 1
	}
	return &pacer{
		interval: interval,
		burst:    time.Duration(burst-1) * interval,
		now:      time.Now,
		tat:      map[string]time.Time{},
	}
}

// reserve advances host's schedule and returns the time the request may proceed.
// Pure bookkeeping, no sleeping. Within the burst allowance it returns now.
func (p *pacer) reserve(host string) time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	base := p.tat[host]
	if base.Before(now) {
		base = now
	}
	sendAt := base.Add(-p.burst)
	if sendAt.Before(now) {
		sendAt = now
	}
	p.tat[host] = base.Add(p.interval)
	if len(p.tat) > pacerMaxHosts {
		for h, t := range p.tat {
			if t.Before(now) {
				delete(p.tat, h)
			}
		}
	}
	return sendAt
}

// wait blocks until host's reserved slot, or until ctx is done or closed is shut,
// whichever is first.
func (p *pacer) wait(ctx context.Context, host string, closed <-chan struct{}) {
	delay := time.Until(p.reserve(host))
	if delay <= 0 {
		return
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	case <-closed:
	}
}

// isLoopback reports whether host is localhost or a loopback IP; such hosts are
// never paced (never a real target).
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
