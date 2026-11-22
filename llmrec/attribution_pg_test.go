package llmrec

import (
	"os"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
	"github.com/google/uuid"
)

func TestRecorderPersistsAttribution(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("requires isolated ARTEX_PG_DSN")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Close() })
	if err := pg.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	taskID := "attribution-" + uuid.NewString()
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM llm_usage WHERE task_id=$1`, taskID) })
	// Reuse the same recorder across unrelated runs, as the production provider does.
	r := Wrap(meteredStreamProvider{}, pg, "fixture", "", "", "", func() bool { return false })
	for _, tc := range []struct {
		session  string
		explicit bool
		id       int64
		instance string
		round    int64
	}{
		{"exp12-worker-i99", false, 99, "", 0},
		{"exp12-worker-i99", true, 42, "work#2", 0},
		{"exp12-planner", true, 0, "planner", 8},
		{"", false, 0, "", 0},
	} {
		ctx := WithTaskID(transcript.WithSessionID(t.Context(), tc.session), taskID)
		if tc.explicit {
			ctx = WithAttribution(ctx, tc.id, tc.instance, tc.round)
		}
		for range r.Stream(ctx, llm.CompletionRequest{}) {
		}
		if _, _, _, err := r.Complete(ctx, llm.CompletionRequest{}); err != nil {
			t.Fatal(err)
		}
		var matches int
		if err := pg.QueryRow(`SELECT count(*) FROM llm_usage WHERE task_id=$1
AND COALESCE(intent_id,0)=$2 AND COALESCE(worker_instance,'')=$3 AND COALESCE(plan_round,0)=$4`,
			taskID, tc.id, tc.instance, tc.round).Scan(&matches); err != nil || matches != 2 {
			t.Fatalf("case=%+v matches=%d err=%v", tc, matches, err)
		}
		if tc.explicit && CallCount(ctx) != 2 {
			t.Fatalf("calls=%d want 2", CallCount(ctx))
		}
	}
}
