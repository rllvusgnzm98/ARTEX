package server

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestLoopbackPprofAddr(t *testing.T) {
	for _, tc := range []struct {
		addr, want string
	}{
		{"127.0.0.1:6060", "127.0.0.1:6060"},
		{"127.23.4.5:0", "127.23.4.5:0"},
		{"localhost:6060", "127.0.0.1:6060"},
		{"[::1]:6060", "[::1]:6060"},
		{"[::ffff:127.0.0.1]:6060", "127.0.0.1:6060"},
		{"", ""}, {":6060", ""}, {"0.0.0.0:6060", ""}, {"[::]:6060", ""},
		{"192.168.1.1:6060", ""}, {"example.com:6060", ""}, {"localhost.example:6060", ""},
		{"127.0.0.1", ""}, {"127.0.0.1:-1", ""}, {"127.0.0.1:65536", ""},
		{"127.0.0.1:http", ""}, {"127.0.0.1:", ""},
	} {
		t.Run(tc.addr, func(t *testing.T) {
			got, err := loopbackPprofAddr(tc.addr)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("unsafe/invalid address accepted: %q", got)
				}
			} else if err != nil || got != tc.want {
				t.Fatalf("address=%q err=%v want %q", got, err, tc.want)
			}
		})
	}
}

func TestPprofOptInAndLifecycle(t *testing.T) {
	if srv := startPprof(t.Context(), ""); srv != nil {
		t.Fatal("pprof enabled with empty address")
	}
	if srv := startPprof(t.Context(), "0.0.0.0:6060"); srv != nil {
		t.Fatal("non-loopback pprof enabled")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	srv := startPprof(ctx, "127.0.0.1:0")
	if srv == nil {
		t.Fatal("loopback pprof did not start")
	}
	t.Cleanup(func() { _ = srv.Close() })
	shutdown := make(chan struct{})
	srv.RegisterOnShutdown(func() { close(shutdown) })
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + srv.Addr + "/debug/pprof/goroutine?debug=1")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("goroutine profile:")) {
		t.Fatalf("pprof response=%d err=%v body=%s", resp.StatusCode, err, body)
	}
	cancel()
	select {
	case <-shutdown:
	case <-time.After(2 * time.Second):
		t.Fatal("context cancellation did not shut pprof down")
	}
	if srv := startPprof(ctx, "127.0.0.1:0"); srv != nil {
		t.Fatal("pprof started with cancelled context")
	}
}

func TestPprofBindFailureIsBestEffort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if srv := startPprof(t.Context(), listener.Addr().String()); srv != nil {
		t.Fatal("pprof started on occupied port")
	}
}

func TestProcessHeartbeatSnapshot(t *testing.T) {
	m := &Manager{tasks: map[string]*Task{
		"running": {Status: "running"},
		"paused":  {Status: "running", Paused: true},
		"queued":  {Status: "running", Queued: true},
		"done":    {Status: "done"},
	}}
	e := NewEngine(m)
	if !e.beginTaskOperation("running") {
		t.Fatal("could not begin operation")
	}
	e.BeginLLMCall("running")
	e.BeginLLMCall("other")
	e.EndLLMCall("other")
	if e.lastLLMStart.Load() == 0 || e.lastLLMFinish.Load() == 0 {
		t.Fatal("call timestamps not recorded")
	}
	now := time.Now()
	e.lastLLMStart.Store(now.Add(-5 * time.Second).UnixNano())
	e.lastLLMFinish.Store(now.Add(-3 * time.Second).UnixNano())
	var output bytes.Buffer
	original := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(original)
	stats := e.logProcessHeartbeat(now, sql.DBStats{})
	if stats != (sql.DBStats{}) {
		t.Fatalf("nil pool stats=%+v", stats)
	}
	for _, want := range []string{"[heartbeat]", "running_tasks=1", "engine_inflight=1", "llm_inflight=1",
		"last_llm_start_s=5.0", "last_llm_finish_s=3.0", "db_in_use=0", "db_idle=0",
		"db_wait_count=0", "db_wait_count_delta=0", "db_wait_duration_delta=0s", "goroutines="} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("heartbeat missing %q: %s", want, output.String())
		}
	}
	if e.ActiveLLMCalls("running") != 1 || e.inflightCount("running") != 1 {
		t.Fatal("heartbeat modified engine accounting")
	}
	if got := secondsSince(now, 0); got != -1 {
		t.Fatalf("never-called age=%v want -1", got)
	}
}

func TestProcessHeartbeatStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	e := NewEngine(nil)
	done := make(chan struct{})
	go func() { defer close(done); e.processHeartbeat(ctx) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("heartbeat did not stop")
	}
}

func TestProcessHeartbeatCountsStartedCreatedTaskAndProviderInflight(t *testing.T) {
	m := &Manager{tasks: map[string]*Task{
		"101": {ID: "101", Status: "created"},
		"102": {ID: "102", Status: "created"},
		"103": {ID: "103", Status: "done"},
	}}
	e := NewEngine(m)
	e.started.Store("101", true)
	e.started.Store("103", true) // terminal must not count even if started bit lingering
	e.beginProviderCall()
	now := time.Now()
	e.lastProviderStart.Store(now.Add(-7 * time.Second).UnixNano())
	e.lastProviderFinish.Store(now.Add(-2 * time.Second).UnixNano())

	var output bytes.Buffer
	original := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(original)

	e.logProcessHeartbeat(now, sql.DBStats{})
	line := output.String()
	for _, want := range []string{"running_tasks=1", "provider_inflight=1", "last_provider_start_s=7.0", "last_provider_finish_s=2.0"} {
		if !strings.Contains(line, want) {
			t.Fatalf("heartbeat missing %q: %s", want, line)
		}
	}
	e.endProviderCall()
	output.Reset()
	e.logProcessHeartbeat(now, sql.DBStats{})
	if !strings.Contains(output.String(), "provider_inflight=0") {
		t.Fatalf("expected provider_inflight=0 after endProviderCall: %s", output.String())
	}
}

