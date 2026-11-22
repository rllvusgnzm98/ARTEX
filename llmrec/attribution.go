package llmrec

import (
	"context"
	"strconv"
	"strings"
	"sync/atomic"
)

type attributionKey struct{}

type attribution struct {
	intentID  int64
	instance  string
	planRound int64
	calls     atomic.Int64
}

// WithAttribution starts a call counter shared by all descendants of this run.
func WithAttribution(ctx context.Context, intentID int64, instance string, planRound int64) context.Context {
	return context.WithValue(ctx, attributionKey{}, &attribution{
		intentID: intentID, instance: instance, planRound: planRound,
	})
}

// CallCount returns the number of recorder calls started in this run.
func CallCount(ctx context.Context) int64 {
	if a, _ := ctx.Value(attributionKey{}).(*attribution); a != nil {
		return a.calls.Load()
	}
	return 0
}

func attributionFrom(ctx context.Context, session string) (int64, string, int64) {
	intentID := intentFromSession(session)
	if a, _ := ctx.Value(attributionKey{}).(*attribution); a != nil {
		if a.intentID > 0 {
			intentID = a.intentID
		}
		return intentID, a.instance, a.planRound
	}
	return intentID, "", 0
}

func countCall(ctx context.Context) {
	if a, _ := ctx.Value(attributionKey{}).(*attribution); a != nil {
		a.calls.Add(1)
	}
}

func intentFromSession(session string) int64 {
	if !strings.HasPrefix(session, "exp") {
		return 0
	}
	exploration, suffix, ok := strings.Cut(session[3:], "-worker-i")
	if !ok {
		return 0
	}
	expID, err := strconv.ParseInt(exploration, 10, 64)
	if err != nil || expID <= 0 {
		return 0
	}
	id, err := strconv.ParseInt(suffix, 10, 64)
	if err != nil || id <= 0 {
		return 0
	}
	return id
}
