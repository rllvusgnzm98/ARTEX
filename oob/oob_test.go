package oob

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAllocateHTTPHandlePollAndPersist(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "oob")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	m, err := New(ctx, dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.SetBaseURL("http://10.0.0.5:8787")

	entry, err := m.Allocate(AllocateOpts{
		TaskID:       "42",
		Label:        "xss-beacon",
		TTL:          30 * time.Minute,
		ResponseBody: "/* ok */",
		ContentType:  "application/javascript",
	})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if !strings.HasPrefix(entry.Token, "o_") || entry.URL != "http://10.0.0.5:8787/o/"+entry.Token {
		t.Fatalf("unexpected entry: %+v", entry)
	}

	// OPTIONS preflight returns 204 with permissive CORS and still logs interaction.
	optReq := httptest.NewRequest(http.MethodOptions, "/o/"+entry.Token, nil)
	optRec := httptest.NewRecorder()
	m.HandleHTTP(optRec, optReq, entry.Token, "")
	if optRec.Code != http.StatusNoContent || optRec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("OPTIONS status=%d cors=%q", optRec.Code, optRec.Header().Get("Access-Control-Allow-Origin"))
	}

	// POST callback with subpath and query.
	postReq := httptest.NewRequest(http.MethodPost, "/o/"+entry.Token+"/exfil?step=dom", strings.NewReader("csrf=abc123"))
	postReq.Header.Set("X-Beacon", "admin-bot")
	postReq.RemoteAddr = "10.0.162.131:44123"
	postRec := httptest.NewRecorder()
	m.HandleHTTP(postRec, postReq, entry.Token, "exfil")
	if postRec.Code != http.StatusOK || postRec.Body.String() != "/* ok */" {
		t.Fatalf("POST status=%d body=%q", postRec.Code, postRec.Body.String())
	}

	// Cross-task isolation fence.
	if _, _, err := m.Poll(t.Context(), "99", entry.Token, 0, 0, 10); err != ErrNotFound {
		t.Fatalf("cross-task poll expected ErrNotFound, got %v", err)
	}
	if m.Delete("99", entry.Token) {
		t.Fatal("cross-task delete must fail")
	}

	evs, gotEntry, err := m.Poll(t.Context(), "42", entry.Token, 0, 0, 10)
	if err != nil || len(evs) != 2 || gotEntry.Hits != 2 {
		t.Fatalf("Poll got len=%d entry=%+v err=%v", len(evs), gotEntry, err)
	}
	if evs[1].Seq != 2 || evs[1].Method != "POST" || evs[1].Query != "step=dom" || evs[1].Body != "csrf=abc123" || evs[1].RemoteIP != "10.0.162.131" {
		t.Fatalf("unexpected second event: %+v", evs[1])
	}

	// Instant wakeup on wait > 0.
	wakeCh := make(chan []Interaction, 1)
	go func() {
		got, _, perr := m.Poll(t.Context(), "42", entry.Token, 2, 5*time.Second, 10)
		if perr == nil {
			wakeCh <- got
		}
	}()
	time.Sleep(25 * time.Millisecond)
	getReq := httptest.NewRequest(http.MethodGet, "/o/"+entry.Token+"/ping", nil)
	m.HandleHTTP(httptest.NewRecorder(), getReq, entry.Token, "ping")
	select {
	case got := <-wakeCh:
		if len(got) != 1 || got[0].Seq != 3 {
			t.Fatalf("unexpected wakeup events: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("Poll did not wake up immediately on callback")
	}

	// Persistence across Manager restart.
	m.Close()
	m2, err := New(ctx, dir)
	if err != nil {
		t.Fatalf("reload New: %v", err)
	}
	defer m2.Close()
	evs2, _, err := m2.Poll(t.Context(), "42", entry.Token, 1, 0, 10)
	if err != nil || len(evs2) != 2 || evs2[0].Seq != 2 || evs2[1].Seq != 3 {
		t.Fatalf("persisted reload events=%+v err=%v", evs2, err)
	}

	// Sweep expired entries.
	m2.sweep(time.Now().Add(time.Hour))
	if _, _, err := m2.Poll(t.Context(), "42", entry.Token, 0, 0, 10); err != ErrNotFound {
		t.Fatalf("expired entry still active: %v", err)
	}
}
