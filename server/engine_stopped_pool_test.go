package server

import (
	"errors"
	"fmt"
	"testing"

	"github.com/Autumn-27/artex/llmpool"
)

func TestStoppedPoolBackupOnlySettlesSupplyFailures(t *testing.T) {
	quota := &llmpool.StoppedFailoverError{Err: errors.New("anthropic: status 402: insufficient_quota")}
	timeout := &llmpool.StoppedFailoverError{Err: fmt.Errorf("call timeout: %w", errors.New("deadline"))}
	if !isSupplyFailure(quota) {
		t.Fatal("stopped 402 with backup must settle as supply_failure")
	}
	if isSupplyFailure(timeout) {
		t.Fatal("stopped timeout must keep its error so the intent reopens")
	}
}
