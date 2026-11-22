package llmrec

import (
	"context"
	"errors"
	"iter"
	"sync"
	"testing"

	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

func TestIntentFromSession(t *testing.T) {
	for _, tc := range []struct {
		session string
		want    int64
	}{
		{"exp12-worker-i99", 99}, {"exp1-worker-i4294967296", 4294967296},
		{"", 0}, {"exp1-planner", 0}, {"exp1-worker", 0}, {"worker-i99", 0},
		{"expX-worker-i99", 0}, {"exp1-worker-i", 0}, {"exp1-worker-i-2", 0},
		{"exp1-worker-i0", 0}, {"exp1-planner-i99", 0}, {"exp1-worker-i99-extra", 0},
		{"exp1-worker-i999999999999999999999", 0},
	} {
		t.Run(tc.session, func(t *testing.T) {
			if got := intentFromSession(tc.session); got != tc.want {
				t.Fatalf("intentFromSession(%q)=%d want %d", tc.session, got, tc.want)
			}
		})
	}
}

func TestAttributionContext(t *testing.T) {
	for _, tc := range []struct {
		name         string
		ctx          context.Context
		wantID       int64
		wantInstance string
		wantRound    int64
	}{
		{"fallback", context.Background(), 99, "", 0},
		{"explicit", WithAttribution(context.Background(), 42, "work#2", 3), 42, "work#2", 3},
		{"fallback with metadata", WithAttribution(context.Background(), 0, "work#1", 4), 99, "work#1", 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, instance, round := attributionFrom(tc.ctx, "exp12-worker-i99")
			if id != tc.wantID || instance != tc.wantInstance || round != tc.wantRound {
				t.Fatalf("attribution=(%d,%q,%d)", id, instance, round)
			}
		})
	}
	if got := CallCount(context.Background()); got != 0 {
		t.Fatalf("unattributed call count=%d", got)
	}
}

type attributedProvider struct {
	t   *testing.T
	err error
}

func (p attributedProvider) check(ctx context.Context) {
	p.t.Helper()
	id, instance, round := attributionFrom(ctx, transcript.SessionIDFrom(ctx))
	if id != 42 || instance != "work#3" || round != 7 {
		p.t.Errorf("inner attribution=(%d,%q,%d)", id, instance, round)
	}
}

func (p attributedProvider) Stream(ctx context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	p.check(ctx)
	return func(yield func(llm.StreamEvent, error) bool) {
		yield(llm.StreamEvent{Type: llm.SEMessageStop}, p.err)
	}
}

func (p attributedProvider) Complete(ctx context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.check(ctx)
	return llm.Message{}, "", llm.Usage{}, p.err
}

func TestRecorderAttributionAndConcurrentCounter(t *testing.T) {
	for _, callErr := range []error{nil, errors.New("provider failure")} {
		for _, captured := range []bool{false, true} {
			ctx := WithAttribution(transcript.WithSessionID(context.Background(), "exp1-worker-i99"), 42, "work#3", 7)
			child, cancel := context.WithCancel(ctx)
			if captured {
				child, _ = NewCapture(child)
			}
			r := Wrap(attributedProvider{t: t, err: callErr}, nil, "fixture", "", "", "", func() bool { return false })
			var wg sync.WaitGroup
			for range 8 {
				wg.Go(func() {
					for _, err := range r.Stream(child, llm.CompletionRequest{}) {
						if !errors.Is(err, callErr) {
							t.Errorf("stream error=%v want %v", err, callErr)
						}
						break
					}
					if _, _, _, err := r.Complete(child, llm.CompletionRequest{}); !errors.Is(err, callErr) {
						t.Errorf("complete error=%v want %v", err, callErr)
					}
				})
			}
			wg.Wait()
			cancel()
			if got := CallCount(ctx); got != 16 {
				t.Fatalf("shared calls=%d want 16", got)
			}
			if got := CallCount(WithAttribution(ctx, 0, "planner", 8)); got != 0 {
				t.Fatalf("new run inherited counter=%d", got)
			}
		}
	}
}

func TestRecorderCountsEmptyCalls(t *testing.T) {
	ctx := WithAttribution(context.Background(), 0, "planner", 1)
	r := Wrap(completeProvider{}, nil, "", "", "", "", func() bool { return false })
	for range r.Stream(ctx, llm.CompletionRequest{}) {
		t.Fatal("unexpected stream event")
	}
	if got := CallCount(ctx); got != 1 {
		t.Fatalf("empty stream calls=%d want 1", got)
	}
	if _, _, _, err := r.Complete(ctx, llm.CompletionRequest{}); err != nil {
		t.Fatal(err)
	}
	if got := CallCount(ctx); got != 2 {
		t.Fatalf("calls=%d want 2", got)
	}
}
