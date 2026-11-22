package intercept

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestHandleAskCancellationResolvesPending(t *testing.T) {
	d := openTestDB(t)
	ic := New(d)
	resetAutoAllow(t, ic)
	for _, timeoutEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("timeout_enabled=%t", timeoutEnabled), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			activities := make(chan db.Activity, 1)
			ctx = WithTaskContext(ctx, "cancel-ask-test", "worker", func(a db.Activity) { activities <- a })
			done := make(chan bool, 1)
			go func() {
				done <- ic.HandleAsk(ctx, 0, Decision{Action: "ask", Message: "cancel test", TimeoutEnabled: timeoutEnabled, TimeoutSeconds: 60}, "Bash", []byte(`{"command":"true"}`))
			}()
			var pendingID int64
			select {
			case activity := <-activities:
				var detail struct {
					PendingID int64 `json:"pending_id"`
				}
				if err := json.Unmarshal([]byte(activity.Detail), &detail); err != nil {
					t.Fatal(err)
				}
				pendingID = detail.PendingID
			case <-time.After(3 * time.Second):
				t.Fatal("ask did not reach pending wait")
			}
			t.Cleanup(func() { _, _ = d.Exec("DELETE FROM intercept_pending WHERE id=$1", pendingID) })
			pending, err := d.GetInterceptDetail(pendingID)
			if err != nil || pending == nil || pending.Status != "pending" {
				t.Fatalf("before cancellation: pending=%+v err=%v", pending, err)
			}
			cancel()
			select {
			case allowed := <-done:
				if allowed {
					t.Fatal("cancelled ask was allowed")
				}
			case <-time.After(4 * time.Second):
				t.Fatal("cancelled ask did not finish within terminal write budget")
			}
			resolved, err := d.GetInterceptDetail(pendingID)
			if err != nil || resolved == nil {
				t.Fatalf("resolved=%+v err=%v", resolved, err)
			}
			if resolved.Status != "denied" || resolved.Audit == nil || resolved.Audit.EffectiveAction != "deny" || resolved.Audit.DecisionReason != "工作已取消" || resolved.Audit.ExecutionStatus != "not_executed" {
				t.Fatalf("cancelled ask not resolved: %+v audit=%+v", resolved, resolved.Audit)
			}
		})
	}
}
