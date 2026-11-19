package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

func TestWebFetchUsesStableTaskUA(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("User-Agent"))
		mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)

	pool := []string{"UA-Task-Stable-A", "UA-Task-Stable-B"}
	taskID := int64(42)
	want := PickUA(pool, taskID)
	if want == "" {
		t.Fatal("PickUA returned empty")
	}
	// 与 BashEnv 注入的 ARTEX_UA 同一来源。
	env := uaEnv(nil, want)
	if len(env) != 1 || env[0] != "ARTEX_UA="+want {
		t.Fatalf("ARTEX_UA mismatch: %v vs %q", env, want)
	}

	tool := NewWebFetchWithUA(actool.WebFetchConfig{}, want)
	raw, _ := json.Marshal(map[string]string{"url": srv.URL + "/page"})
	res, err := tool.Call(context.Background(), raw, &actool.ToolContext{})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("WebFetch error: %s", res.Flatten())
	}

	// 同一 taskID 再发一次，UA 必须稳定。
	res2, err := tool.Call(context.Background(), raw, &actool.ToolContext{})
	if err != nil || res2.IsError {
		t.Fatalf("second fetch: %v %s", err, res2.Flatten())
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("expected 2 requests, got %v", seen)
	}
	if seen[0] != want || seen[1] != want {
		t.Fatalf("WebFetch UA = %v, want stable %q (PickUA/ARTEX_UA)", seen, want)
	}
	if PickUA(pool, taskID) != want {
		t.Fatal("PickUA must be stable for the same taskID")
	}
}

func TestWebFetchNameIsOfficial(t *testing.T) {
	tool := NewWebFetchWithUA(actool.WebFetchConfig{}, "UA-X")
	if tool.Name() != "WebFetch" {
		t.Fatalf("got %q", tool.Name())
	}
}
