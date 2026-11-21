package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestCompressionPassSignalsProviderFailures(t *testing.T) {
	for _, pass := range []string{"minor", "major", "minor_then_major"} {
		for _, outcome := range []string{"failure", "mixed", "success", "canceled", "deadline", "provider_deadline"} {
			t.Run(pass+"/"+outcome, func(t *testing.T) {
				_, ts := retentionStore(t)
				steps := []scriptedComplete{{err: errors.New("provider 503")}}
				wantFailure := true
				runCtx := t.Context()
				switch outcome {
				case "mixed":
					steps = append(steps, scriptedComplete{text: "retained observations"})
				case "success":
					steps[0] = scriptedComplete{text: "retained observations"}
					wantFailure = false
				case "canceled":
					steps[0].err = fmt.Errorf("provider stopped: %w", context.Canceled)
					wantFailure = false
				case "deadline":
					steps[0].err = fmt.Errorf("provider stopped: %w", context.DeadlineExceeded)
					var cancel context.CancelFunc
					runCtx, cancel = context.WithDeadline(runCtx, time.Now().Add(-time.Second))
					t.Cleanup(cancel)
					wantFailure = false
				case "provider_deadline":
					steps[0].err = fmt.Errorf("provider timed out: %w", context.DeadlineExceeded)
				}
				for range len(steps) {
					intent, err := ts.AddNode(db.KindIntent, map[string]any{"summary": "settled"}, 0, "done", "test", nil)
					if err != nil {
						t.Fatal(err)
					}
					fact, err := ts.AddNode(db.KindFact, map[string]any{"summary": "observation"}, 0, "confirmed", "test", nil)
					if err != nil {
						t.Fatal(err)
					}
					if err := ts.Link(intent, db.RelYields, fact); err != nil {
						t.Fatal(err)
					}
				}
				provider := &scriptedCompactorProvider{steps: steps}
				c := NewCompactor(provider, "test")
				c.params.R = 0
				if pass == "minor_then_major" {
					c.m = 1
				}
				if _, _, _, err := c.maintain(ts); err != nil {
					t.Fatal(err)
				}
				if pass == "major" {
					c.major(runCtx, ts)
				} else {
					c.minor(runCtx, ts)
				}
				if provider.callCount() < len(steps) {
					t.Fatalf("only %d provider calls, want at least %d", provider.callCount(), len(steps))
				}
				reason, err := ts.GraphIncompleteReason()
				if err != nil {
					t.Fatal(err)
				}
				if (reason != "") != wantFailure {
					t.Fatalf("reason=%q, wantFailure=%v", reason, wantFailure)
				}
				overview := NewToolSet(ts, "planner").graphOverviewData()
				if wantFailure {
					if overview["graph_incomplete"] != true || overview["graph_incomplete_reason"] != reason {
						t.Errorf("missing failure signal in overview: %v", overview)
					}
					hint, _ := overview["graph_incomplete_hint"].(string)
					if !strings.Contains(hint, "expand_digest") || !strings.Contains(hint, "node_detail") {
						t.Errorf("missing recovery instructions: %q", hint)
					}
				} else {
					for _, key := range []string{"graph_incomplete", "graph_incomplete_reason", "graph_incomplete_hint"} {
						if _, exists := overview[key]; exists {
							t.Errorf("unexpected %s when not incomplete", key)
						}
					}
				}
				if outcome == "mixed" {
					digests, err := ts.ActiveDigests()
					if err != nil || len(digests) == 0 {
						t.Fatalf("mixed pass must also commit a successful block: digests=%v err=%v", digests, err)
					}
				}
			})
		}
	}
}
