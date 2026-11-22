package server

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func sumEngineCounters(counters *sync.Map) int64 {
	var total int64
	counters.Range(func(_, value any) bool {
		total += max(0, atomic.LoadInt64(value.(*int64)))
		return true
	})
	return total
}

func secondsSince(now time.Time, timestamp int64) float64 {
	if timestamp == 0 {
		return -1
	}
	return max(0, now.Sub(time.Unix(0, timestamp)).Seconds())
}

func (e *Engine) logProcessHeartbeat(now time.Time, previous sql.DBStats) sql.DBStats {
	running := 0
	var stats sql.DBStats
	if e.m != nil {
		for _, task := range e.m.List() {
			state := task.lifecycleSnapshot()
			if state.Status == "running" && !state.Paused && !state.Queued {
				running++
			}
		}
		if e.m.pg != nil {
			stats = e.m.pg.Stats()
		}
	}
	log.Printf("[heartbeat] running_tasks=%d engine_inflight=%d llm_inflight=%d last_llm_start_s=%.1f last_llm_finish_s=%.1f db_in_use=%d db_idle=%d db_wait_count=%d db_wait_count_delta=%d db_wait_duration_delta=%s goroutines=%d",
		running, sumEngineCounters(&e.inflight), sumEngineCounters(&e.llmCalls),
		secondsSince(now, e.lastLLMStart.Load()), secondsSince(now, e.lastLLMFinish.Load()),
		stats.InUse, stats.Idle, stats.WaitCount, stats.WaitCount-previous.WaitCount, stats.WaitDuration-previous.WaitDuration, runtime.NumGoroutine())
	return stats
}

func (e *Engine) processHeartbeat(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	var previous sql.DBStats
	if e.m != nil && e.m.pg != nil {
		previous = e.m.pg.Stats()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if ctx.Err() != nil {
				return
			}
			previous = e.logProcessHeartbeat(now, previous)
		}
	}
}

func loopbackPprofAddr(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("pprof host must be a loopback IP or localhost")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return "", fmt.Errorf("invalid pprof port")
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(n)), nil
}

func startPprof(ctx context.Context, addr string) *http.Server {
	addr = strings.TrimSpace(addr)
	if addr == "" || ctx.Err() != nil {
		return nil
	}
	addr, err := loopbackPprofAddr(addr)
	if err != nil {
		log.Printf("[pprof] 跳过 ARTEX_PPROF_ADDR: %v", err)
		return nil
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[pprof] 监听失败: %v", err)
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /debug/pprof/", pprof.Index)
	mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
	srv := &http.Server{Addr: listener.Addr().String(), Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("[pprof] 服务失败: %v", err)
		}
	}()
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := srv.Shutdown(shutdownCtx); err != nil {
				log.Printf("[pprof] 关闭失败: %v", err)
				_ = srv.Close()
			}
		case <-done:
		}
	}()
	log.Printf("[pprof] listening on %s", srv.Addr)
	return srv
}
