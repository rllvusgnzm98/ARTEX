package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

const credFixturePass = "fixture-pass"

func TestIntranetListCredentialsRedactsSecret(t *testing.T) {
	pg := openIntranetTestDB(t)
	cs := db.NewCredentialStore(pg, []byte("intranet-test-master-key"))
	s := &Server{credStore: cs}
	ctx := context.Background()
	id, err := cs.Create(ctx, &db.CredentialRecord{
		TaskID: 980021, Username: "fixture-admin", CredType: "password",
		Secret: credFixturePass, Source: "fixture source ssh",
	})
	if err != nil {
		t.Fatalf("凭据落库失败: %v", err)
	}
	t.Cleanup(func() { _ = cs.Delete(context.Background(), id) })

	items := doListItems(t, s.intranetListCredentials, "/api/credentials?task_id=980021")
	if len(items) != 1 {
		t.Fatalf("应 1 条: %d", len(items))
	}
	raw, _ := json.Marshal(items[0])
	if strings.Contains(string(raw), credFixturePass) {
		t.Fatalf("GET /api/credentials 不得回显明文 secret: %s", raw)
	}
	it, _ := items[0].(map[string]any)
	if _, ok := it["secret"]; ok {
		t.Fatalf("列表不得含 secret 字段: %s", raw)
	}
	if it["secret_masked"] == nil || it["secret_masked"] == credFixturePass {
		t.Fatalf("应含脱敏字段且不等于明文: %#v", it)
	}

	other, err := cs.Create(ctx, &db.CredentialRecord{
		TaskID: 980022, CredType: "password", Secret: "fixture-other", Source: "t",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Delete(context.Background(), other) })
	if all := doListItems(t, s.intranetListCredentials, "/api/credentials"); len(all) < 2 {
		t.Fatalf("全局视图应至少 2 条: %d", len(all))
	}
	expectBadTaskID(t, s.intranetListCredentials, "/api/credentials?task_id=0")
}

func TestCredentialToolsListRedactsReuseIncludesSecret(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { m.Close() })

	task, err := m.CreateTaskWithOptions("cred fixture", "fixture goal", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	taskID := mustTaskID(t, task.ID)
	srcID, err := m.Assets().UpsertIP(db.UpsertIPReq{IP: "10.0.0.5", TaskID: taskID})
	if err != nil {
		t.Fatalf("UpsertIP src: %v", err)
	}
	if _, err := m.Assets().UpsertIP(db.UpsertIPReq{
		IP: "10.0.0.9", TaskID: taskID,
		OpenPorts: []db.PortService{{Port: 22, Service: "ssh"}},
	}); err != nil {
		t.Fatalf("UpsertIP cand: %v", err)
	}

	cs := db.NewCredentialStore(m.PG(), []byte("intranet-test-master-key"))
	s := &Server{credStore: cs, m: m}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: taskID})
	id, err := cs.Create(ctx, &db.CredentialRecord{
		TaskID: taskID, Username: "fixture-admin", CredType: "password",
		Secret: credFixturePass, Domain: "FIXTURE", Source: "10.0.0.5 fixture source ssh",
		HostAssetID: srcID,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = cs.Delete(context.Background(), id) })

	listRes, err := s.listCredentialsTool().Call(ctx, json.RawMessage(`{}`), &actool.ToolContext{})
	if err != nil {
		t.Fatal(err)
	}
	listOut := toolResultJSON(t, listRes)
	listRaw, _ := json.Marshal(listOut)
	if strings.Contains(string(listRaw), credFixturePass) {
		t.Fatalf("list_credentials 不得回显明文: %s", listRaw)
	}

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	planRes, err := s.credentialReusePlanTool().Call(ctx, json.RawMessage(`{}`), &actool.ToolContext{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), credFixturePass) {
		t.Fatalf("日志不得打印口令: %s", buf.String())
	}
	planOut := toolResultJSON(t, planRes)
	planRaw, _ := json.Marshal(planOut)
	sugs, _ := planOut["suggestions"].([]any)
	if len(sugs) == 0 {
		t.Fatalf("应有复用建议: %s", planRaw)
	}
	if !strings.Contains(string(planRaw), credFixturePass) {
		t.Fatalf("工人复用路径的工具返回必须含必要 secret 字段: %s", planRaw)
	}
	first, _ := sugs[0].(map[string]any)
	if first["secret"] != credFixturePass || first["username"] != "fixture-admin" {
		t.Fatalf("建议应含复用必要字段: %#v", first)
	}

	redacted := db.RedactCredentialPayload("credential_reuse_plan", string(planRaw))
	if strings.Contains(redacted, credFixturePass) {
		t.Fatalf("活动日志清洗后不得含明文: %s", redacted)
	}
}
