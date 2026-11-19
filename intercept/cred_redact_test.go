package intercept

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

const credInterceptFixturePass = "fixture-pass"

func TestMatchStillSeesRawCredentialInput(t *testing.T) {
	d := openInterceptTestDB(t)
	ic := New(d)
	rule, err := d.CreateInterceptRule(
		"cred-input-fixture", "tool_input", "string", credInterceptFixturePass,
		"ask", "fixture ask", 50, true, false, 0, "",
	)
	if err != nil {
		t.Fatalf("CreateInterceptRule: %v", err)
	}
	t.Cleanup(func() { _ = d.DeleteInterceptRule(rule.ID) })
	ic.Invalidate()

	raw := []byte(`{"cred_type":"password","secret":"fixture-pass","source":"fixture source","username":"fixture-admin"}`)
	dec, ok := ic.Match("add_credential", raw)
	if !ok || dec.Action != "ask" {
		t.Fatalf("Match 必须看原始 input（含明文）才能命中 tool_input 规则, got ok=%v dec=%+v", ok, dec)
	}

	// 清洗后的文本不再含明文，证明「若在 Match 前清洗就会漏掉这条规则」。
	stored := RedactStoredToolInput("add_credential", raw)
	if strings.Contains(string(stored), credInterceptFixturePass) {
		t.Fatalf("持久化视图不得含明文: %s", stored)
	}
	if _, ok := ic.Match("add_credential", stored); ok {
		t.Fatal("清洗后再 Match 不应再命中以明文为 pattern 的规则（对照：Match 必须用原始 input）")
	}
}

func TestHandleAskAndLogRedactCredentialInput(t *testing.T) {
	d := openInterceptTestDB(t)
	ic := New(d)
	raw := []byte(`{"cred_type":"password","secret":"fixture-pass","source":"fixture source","username":"fixture-admin"}`)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var emitted db.Activity
	ctx = WithTaskContext(ctx, "cred-redact-ask", "worker", func(a db.Activity) { emitted = a })

	done := make(chan bool, 1)
	go func() {
		done <- ic.HandleAsk(ctx, 0, Decision{Action: "ask", Message: "fixture ask"}, "add_credential", raw)
	}()

	var pending *db.InterceptPending
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		items, err := d.ListPendingIntercepts()
		if err != nil {
			t.Fatalf("ListPendingIntercepts: %v", err)
		}
		for _, p := range items {
			if p.ToolName == "add_credential" && p.TaskID != nil && *p.TaskID == "cred-redact-ask" {
				cp := p
				pending = &cp
				break
			}
		}
		if pending != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if pending == nil {
		t.Fatal("HandleAsk 未写入 pending")
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM intercept_pending WHERE id=$1`, pending.ID) })

	if strings.Contains(string(pending.ToolInput), credInterceptFixturePass) {
		t.Fatalf("pending.tool_input 不得含明文 secret: %s", pending.ToolInput)
	}
	if emitted.Kind != "intercept_request" {
		t.Fatalf("应写出 intercept_request 活动, got %+v", emitted)
	}
	if strings.Contains(emitted.Detail, credInterceptFixturePass) {
		t.Fatalf("intercept_request 活动不得含明文 secret: %s", emitted.Detail)
	}
	var detail map[string]any
	if err := json.Unmarshal([]byte(emitted.Detail), &detail); err != nil {
		t.Fatalf("activity detail JSON: %v", err)
	}

	if err := ic.Decide(pending.ID, false); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("HandleAsk 未结束")
	}

	ic.Log(context.Background(), 0, Decision{Action: "deny", Message: "fixture log"}, "add_credential", raw, "denied")
	items, err := d.ListAllIntercepts(50)
	if err != nil {
		t.Fatalf("ListAllIntercepts: %v", err)
	}
	var logged *db.InterceptApprovalRow
	for i := range items {
		if items[i].ToolName == "add_credential" && items[i].Status == "denied" && items[i].Reason == "fixture log" {
			logged = &items[i]
			break
		}
	}
	if logged == nil {
		t.Fatal("Log 未写入已决行")
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM intercept_pending WHERE id=$1`, logged.ID) })
	if strings.Contains(string(logged.ToolInput), credInterceptFixturePass) {
		t.Fatalf("Log 已决行 tool_input 不得含明文 secret: %s", logged.ToolInput)
	}
}
