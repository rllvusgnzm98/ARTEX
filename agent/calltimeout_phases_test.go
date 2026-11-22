package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/norma/llm"
)

func collectCallTimeout(t *testing.T, p *callTimeoutProvider, consume func(llm.StreamEvent)) *CallTimeoutError {
	t.Helper()
	var result error
	for ev, err := range p.Stream(t.Context(), llm.CompletionRequest{}) {
		if err != nil {
			result = err
		} else if consume != nil {
			consume(ev)
		}
	}
	var timeout *CallTimeoutError
	if !errors.As(result, &timeout) {
		t.Fatalf("error=%v want CallTimeoutError", result)
	}
	if !timeout.Streaming || timeout.ProviderWait+timeout.DownstreamYield > timeout.Elapsed {
		t.Fatalf("invalid phase accounting: %+v", *timeout)
	}
	return timeout
}

func TestCallTimeoutSlowFirstEventTiming(t *testing.T) {
	const firstDelay = 20 * time.Millisecond
	inner := captureUsageProvider{stream: func(ctx context.Context, yield func(llm.StreamEvent, error) bool) {
		time.Sleep(firstDelay)
		if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: "first"}, nil) {
			return
		}
		<-ctx.Done()
		yield(llm.StreamEvent{}, ctx.Err())
	}}
	p := &callTimeoutProvider{inner: inner, timeout: 80 * time.Millisecond}
	got := collectCallTimeout(t, p, nil)
	if got.TimeToFirstEvent < firstDelay || got.ProviderWait < firstDelay {
		t.Fatalf("slow first event missing from timings: %+v", *got)
	}
	for _, text := range []string{"首包=", "等待provider=", "下游yield=", "超时后返回延迟="} {
		if !strings.Contains(got.Error(), text) {
			t.Fatalf("missing %q in %s", text, got.Error())
		}
	}
}

func TestCallTimeoutDownstreamYieldTiming(t *testing.T) {
	const blocked = 40 * time.Millisecond
	inner := captureUsageProvider{stream: func(ctx context.Context, yield func(llm.StreamEvent, error) bool) {
		if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: "first"}, nil) {
			return
		}
		<-ctx.Done()
		yield(llm.StreamEvent{}, ctx.Err())
	}}
	p := &callTimeoutProvider{inner: inner, timeout: 10 * time.Millisecond}
	got := collectCallTimeout(t, p, func(llm.StreamEvent) { time.Sleep(blocked) })
	if got.DownstreamYield < blocked || got.DeadlineReturnDelay < blocked-p.timeout {
		t.Fatalf("consumer blocking not attributed: %+v", *got)
	}
}

func TestCallTimeoutProviderIgnoresContextTiming(t *testing.T) {
	const ignored = 30 * time.Millisecond
	inner := captureUsageProvider{stream: func(ctx context.Context, yield func(llm.StreamEvent, error) bool) {
		<-ctx.Done()
		time.Sleep(ignored)
		yield(llm.StreamEvent{}, ctx.Err())
	}}
	p := &callTimeoutProvider{inner: inner, timeout: 10 * time.Millisecond}
	got := collectCallTimeout(t, p, nil)
	if got.TimeToFirstEvent != 0 || got.DownstreamYield != 0 || got.ProviderWait < p.timeout+ignored || got.DeadlineReturnDelay < ignored {
		t.Fatalf("ignored cancellation not attributed to provider: %+v", *got)
	}
	if !strings.Contains(got.Error(), "首包=未收到") {
		t.Fatalf("missing no-first-event marker: %v", got)
	}
	_, _, _, err := p.Complete(t.Context(), llm.CompletionRequest{})
	var complete *CallTimeoutError
	if !errors.As(err, &complete) {
		t.Fatalf("complete error=%v want CallTimeoutError", err)
	}
	if complete.Streaming || complete.Elapsed < p.timeout+ignored || complete.DeadlineReturnDelay < ignored {
		t.Fatalf("complete timings=%+v", *complete)
	}
	if complete.ProviderWait != 0 || complete.DownstreamYield != 0 || complete.TimeToFirstEvent != 0 {
		t.Fatalf("complete has stream phases: %+v", *complete)
	}
	if strings.Contains(complete.Error(), "首包=") || !strings.Contains(complete.Error(), "超时后返回延迟=") {
		t.Fatalf("incorrect complete phase text: %v", complete)
	}
}

func TestCallTimeoutTimingPreservesSuccessfulExpiredCalls(t *testing.T) {
	inner := captureUsageProvider{stream: func(ctx context.Context, _ func(llm.StreamEvent, error) bool) {
		<-ctx.Done()
	}}
	p := &callTimeoutProvider{inner: inner, timeout: time.Millisecond}
	for _, err := range p.Stream(t.Context(), llm.CompletionRequest{}) {
		if err != nil {
			t.Fatalf("nil provider error changed to %v", err)
		}
	}
	if _, _, _, err := p.Complete(t.Context(), llm.CompletionRequest{}); err != nil {
		t.Fatalf("nil complete error changed to %v", err)
	}
}
