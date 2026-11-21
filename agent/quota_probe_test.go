package agent

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestQuotaTransportLargeBodyStreamsAndClassifies(t *testing.T) {
	quota := `{"error":{"message":"insufficient balance"}}`
	big := quota + strings.Repeat("x", 3*quotaProbeMaxBytes)
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"small quota", quota, http.StatusPaymentRequired},
		{"large quota", big, http.StatusPaymentRequired},
		{"large transient", strings.Repeat("y", 3*quotaProbeMaxBytes), http.StatusTooManyRequests},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, tc.body)
		}))
		req, _ := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader("{}"))
		resp, err := quotaAwareTransport{base: http.DefaultTransport}.RoundTrip(req)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		got, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		srv.Close()
		if resp.StatusCode != tc.want {
			t.Fatalf("%s: status %d want %d", tc.name, resp.StatusCode, tc.want)
		}
		if string(got) != tc.body {
			t.Fatalf("%s: body not preserved (%d vs %d bytes)", tc.name, len(got), len(tc.body))
		}
	}
}
