package llmrec

import (
	"context"
	"errors"
	"iter"
	"os"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
	"github.com/google/uuid"
)

// net/http 只把 userinfo 口令盖成 ***，查询串里的 key= 和纯令牌用户名会原样进 err.Error()。
type urlErrStreamProvider struct{ completeProvider }

func (urlErrStreamProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		yield(llm.StreamEvent{}, errors.New(`Post "https://SECRETTOKEN@api.example.com/v1beta/models?key=SECRETKEY&alt=sse": dial tcp: connect: connection refused`))
	}
}

func TestRecorderRedactsCredentialURLsInStoredError(t *testing.T) {
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
	if err := pg.EnsureLLMRecordsTable(); err != nil {
		t.Fatal(err)
	}
	taskID := "redact-" + uuid.NewString()
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM llm_records WHERE task_id=$1`, taskID)
		_, _ = pg.Exec(`DELETE FROM llm_usage WHERE task_id=$1`, taskID)
	})
	r := Wrap(urlErrStreamProvider{}, pg, "fixture", "", "", "", func() bool { return true })
	ctx := WithTaskID(transcript.WithSessionID(t.Context(), "redact-worker"), taskID)
	for range r.Stream(ctx, llm.CompletionRequest{}) {
	}
	var stored string
	if err := pg.QueryRow(`SELECT COALESCE(error,'') FROM llm_records WHERE task_id=$1`, taskID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, "SECRET") {
		t.Fatalf("stored error leaks credentials: %q", stored)
	}
	if !strings.Contains(stored, "api.example.com") || !strings.Contains(stored, "connection refused") {
		t.Fatalf("stored error lost diagnostic context: %q", stored)
	}
}
