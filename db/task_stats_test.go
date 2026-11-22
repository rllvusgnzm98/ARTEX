package db

import (
	"context"
	"errors"
	"testing"
)

func TestTaskStatsQueriesHonorRequestCancellation(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := d.TaskPlanRoundsSummary(ctx, "not-a-task"); !errors.Is(err, context.Canceled) {
		t.Fatalf("round query error=%v want cancellation", err)
	}
	if _, err := d.TaskLLMStats(ctx, "not-a-task"); !errors.Is(err, context.Canceled) {
		t.Fatalf("usage query error=%v want cancellation", err)
	}
}
