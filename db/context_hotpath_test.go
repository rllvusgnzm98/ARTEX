package db

import (
	"context"
	"testing"
	"time"
)

// TestContextBoundHotPathWrites exercises the cancellation boundaries used by
// workers while a separate transaction holds the affected tables locked.
// TestMain holds the cross-package advisory lock 7337741002.
func TestContextBoundHotPathWrites(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("context hot path", "cancellation")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = d.Exec("DELETE FROM explorations WHERE id=$1", expID) }()
	store := d.Exploration(expID)
	intentID, err := store.AddIntent(map[string]any{"summary": "locked intent"}, 1, nil, "test")
	if err != nil {
		t.Fatal(err)
	}

	locker, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Rollback() //nolint:errcheck
	if _, err := locker.Exec("LOCK TABLE llm_usage, activity, exploration_nodes IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}

	deadlineCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	start := time.Now()
	usageErr := d.InsertLLMUsageCtx(deadlineCtx, &LLMUsage{TaskID: "context-hot-path", Worker: "worker", Model: "test", Status: "ok"})
	cancel()
	if usageErr == nil {
		t.Fatal("locked usage insert unexpectedly succeeded")
	}
	if deadlineCtx.Err() != context.DeadlineExceeded {
		t.Fatalf("usage insert failed before its deadline: %v", usageErr)
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("usage insert exceeded timeout margin: %s", elapsed)
	}

	activityCtx, activityCancel := context.WithTimeout(context.Background(), 3*time.Second)
	start = time.Now()
	_, activityErr := store.AppendActivityCtx(activityCtx, Activity{Worker: "worker", Kind: "text", Summary: "locked"})
	activityCancel()
	if activityErr == nil {
		t.Fatal("locked activity insert unexpectedly succeeded")
	}
	if activityCtx.Err() != context.DeadlineExceeded {
		t.Fatalf("activity insert failed before its deadline: %v", activityErr)
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("activity insert exceeded timeout margin: %s", elapsed)
	}

	toolCtx, toolCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	start = time.Now()
	_, toolErr := store.AddNodeCtx(toolCtx, KindFact, map[string]any{"summary": "cancelled"}, 1, "confirmed", "test", nil)
	toolCancel()
	if toolErr == nil {
		t.Fatal("cancelled tool write unexpectedly succeeded")
	}
	if toolCtx.Err() != context.DeadlineExceeded {
		t.Fatalf("tool write failed before cancellation: %v", toolErr)
	}
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Fatalf("cancelled tool write did not abort promptly: %s", elapsed)
	}

	// The worker run context is already cancelled, but terminal accounting must
	// retain a short cancellation-independent window after the lock is released.
	runCtx, runCancel := context.WithCancel(context.Background())
	runCancel()
	terminalCtx, terminalCancel := context.WithTimeout(context.WithoutCancel(runCtx), 3*time.Second)
	defer terminalCancel()
	type terminalResult struct {
		changed bool
		err     error
	}
	result := make(chan terminalResult, 1)
	go func() {
		changed, err := store.CompareAndSetIntentStateCtx(terminalCtx, intentID, "open", "done")
		result <- terminalResult{changed, err}
	}()
	select {
	case got := <-result:
		t.Fatalf("terminal write returned while lock held: %+v", got)
	case <-time.After(200 * time.Millisecond):
	}
	if err := locker.Commit(); err != nil {
		t.Fatal(err)
	}
	var got terminalResult
	select {
	case got = <-result:
	case <-time.After(4 * time.Second):
		t.Fatal("terminal write exceeded timeout margin")
	}
	changed, err := got.changed, got.err
	if err != nil {
		t.Fatalf("terminal write after cancellation failed: %v", err)
	}
	if !changed {
		t.Fatal("terminal write did not change intent state")
	}

	var state string
	if err := d.QueryRow("SELECT state FROM exploration_nodes WHERE id=$1", intentID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "done" {
		t.Fatalf("terminal state = %q, want done", state)
	}
}
