package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestBatchNodeDetailSupportsSingleAndMultiIDs(t *testing.T) {
	_, ts := retentionStore(t)
	f1, err := ts.AddNode(db.KindFact, map[string]any{"summary": "fact one", "detail": "d1"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	f2, err := ts.AddNode(db.KindFact, map[string]any{"summary": "fact two", "detail": "d2"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	tool := NewToolSet(ts, "planner").nodeDetail()

	// Single id preserves backwards-compatible single-node JSON shape.
	singleRes, err := tool.Call(t.Context(), json.RawMessage(fmt.Sprintf(`{"id":%d}`, f1)), nil)
	if err != nil || singleRes.IsError {
		t.Fatalf("single node_detail failed: err=%v res=%s", err, singleRes.Flatten())
	}
	var singleNode db.Node
	if err := json.Unmarshal([]byte(singleRes.Flatten()), &singleNode); err != nil || singleNode.ID != f1 {
		t.Fatalf("unexpected single node_detail response: err=%v body=%s", err, singleRes.Flatten())
	}

	// Batch ids fetches multiple nodes in one call, deduplicating and reporting missing IDs.
	batchIn := fmt.Sprintf(`{"ids":[%d, %d, %d, 999999999]}`, f1, f2, f1)
	batchRes, err := tool.Call(t.Context(), json.RawMessage(batchIn), nil)
	if err != nil || batchRes.IsError {
		t.Fatalf("batch node_detail failed: err=%v res=%s", err, batchRes.Flatten())
	}
	var out struct {
		Nodes   []db.Node `json:"nodes"`
		Missing []int64   `json:"missing"`
	}
	if err := json.Unmarshal([]byte(batchRes.Flatten()), &out); err != nil {
		t.Fatalf("unmarshal batch response: %v body=%s", err, batchRes.Flatten())
	}
	if len(out.Nodes) != 2 || out.Nodes[0].ID != f1 || out.Nodes[1].ID != f2 {
		t.Fatalf("expected [f1, f2], got %+v", out.Nodes)
	}
	if len(out.Missing) != 1 || out.Missing[0] != 999999999 {
		t.Fatalf("expected missing [999999999], got %+v", out.Missing)
	}
}

func TestCompactorStopsImmediatelyWhenContextExpired(t *testing.T) {
	_, ts := retentionStore(t)
	for i := 0; i < 3; i++ {
		intent, err := ts.AddNode(db.KindIntent, map[string]any{"summary": fmt.Sprintf("intent %d", i)}, 0, "done", "test", nil)
		if err != nil {
			t.Fatal(err)
		}
		fact, err := ts.AddNode(db.KindFact, map[string]any{"summary": fmt.Sprintf("fact %d", i)}, 0, "confirmed", "test", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := ts.Link(intent, db.RelYields, fact); err != nil {
			t.Fatal(err)
		}
	}
	provider := &scriptedCompactorProvider{steps: []scriptedComplete{
		{err: context.DeadlineExceeded},
		{err: errors.New("block 2 must not run after deadline")},
		{err: errors.New("block 3 must not run after deadline")},
	}}
	c := NewCompactor(provider, "test")
	c.params.R = 0
	if _, _, _, err := c.maintain(ts); err != nil {
		t.Fatal(err)
	}
	expired, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	c.minor(expired, ts)
	if got := provider.callCount(); got != 1 {
		t.Fatalf("compactor must stop after first deadline hit and not cascade across remaining blocks, got %d calls", got)
	}
}
