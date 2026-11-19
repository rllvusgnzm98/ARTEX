package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

const credFixturePass = "fixture-pass"

// doListCredentials 解析 GET /api/credentials 响应，校验 200 且含 skipped 计数。
func doListCredentials(t *testing.T, h http.HandlerFunc, url string) (items []any, skipped int, raw []byte) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s 状态码 = %d, body = %q", url, w.Code, w.Body.String())
	}
	raw = w.Body.Bytes()
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("响应 JSON 解析失败: %v (%q)", err, raw)
	}
	items, _ = body["items"].([]any)
	switch v := body["skipped"].(type) {
	case float64:
		skipped = int(v)
	default:
		t.Fatalf("响应必须含数字 skipped, got %#v body=%s", body["skipped"], raw)
	}
	return items, skipped, raw
}

func assertNoSecretMaterial(t *testing.T, raw []byte, logs string) {
	t.Helper()
	blob := string(raw) + "\n" + logs
	for _, needle := range []string{credFixturePass, "fixture-other-key", "gcm1:"} {
		if strings.Contains(blob, needle) {
			t.Fatalf("响应或日志不得含明文 secret/密文: needle=%q body=%s logs=%s", needle, raw, logs)
		}
	}
}

func assertUndecryptablePlaceholder(t *testing.T, m map[string]any, wantID int64, raw []byte) {
	t.Helper()
	if m["status"] != db.CredentialStatusUndecryptable {
		t.Fatalf("坏行应为 status=%s 占位: %#v body=%s", db.CredentialStatusUndecryptable, m, raw)
	}
	for _, k := range []string{"secret", "secret_masked", "username", "cred_type", "domain", "source", "task_id"} {
		if _, ok := m[k]; ok {
			t.Fatalf("占位不得含 %s 或其他凭据字段: %#v", k, m)
		}
	}
	if len(m) != 2 {
		t.Fatalf("占位只含 id 和 status: %#v", m)
	}
	id, _ := m["id"].(float64)
	if int64(id) != wantID {
		t.Fatalf("占位 id 不匹配: %#v want %d", m, wantID)
	}
}

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

func TestIntranetListCredentialsSkipsUndecryptable(t *testing.T) {
	pg := openIntranetTestDB(t)
	goodKey := []byte("intranet-test-master-key")
	cs := db.NewCredentialStore(pg, goodKey)
	other := db.NewCredentialStore(pg, []byte("another-master-key-32bytes!!!!"))
	s := &Server{credStore: cs}
	ctx := context.Background()

	gid, err := cs.Create(ctx, &db.CredentialRecord{
		TaskID: 980041, Username: "fixture-admin", CredType: "password",
		Secret: credFixturePass, Source: "fixture source",
	})
	if err != nil {
		t.Fatalf("Create good: %v", err)
	}
	t.Cleanup(func() { _ = cs.Delete(context.Background(), gid) })
	bid, err := other.Create(ctx, &db.CredentialRecord{
		TaskID: 980042, Username: "other", CredType: "password",
		Secret: "fixture-other-key", Source: "t",
	})
	if err != nil {
		t.Fatalf("Create other: %v", err)
	}
	t.Cleanup(func() { _ = other.Delete(context.Background(), bid) })

	var logBuf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(prev)

	all, skipped, raw := doListCredentials(t, s.intranetListCredentials, "/api/credentials")
	assertNoSecretMaterial(t, raw, logBuf.String())
	var foundGood, foundBad bool
	for _, it := range all {
		m, _ := it.(map[string]any)
		id, _ := m["id"].(float64)
		if int64(id) == gid {
			foundGood = true
			if _, ok := m["secret"]; ok {
				t.Fatalf("可解行仍不得含 secret 字段: %s", raw)
			}
			if m["secret_masked"] == nil || m["secret_masked"] == credFixturePass {
				t.Fatalf("可解行应含脱敏字段: %#v", m)
			}
			if m["status"] != nil {
				t.Fatalf("可解行不应带 undecryptable 状态: %#v", m)
			}
		}
		if int64(id) == bid {
			foundBad = true
			assertUndecryptablePlaceholder(t, m, bid, raw)
		}
	}
	if !foundGood {
		t.Fatalf("GET /api/credentials 应含可解行, body=%s", raw)
	}
	if !foundBad {
		t.Fatalf("无法解密的行应以占位出现在 items 中, body=%s", raw)
	}
	if skipped != 1 {
		t.Fatalf("顶层 skipped 应对调用方可见且为 1, got %d body=%s", skipped, raw)
	}
	if !strings.Contains(logBuf.String(), "skip credential") || !strings.Contains(logBuf.String(), strconv.FormatInt(bid, 10)) {
		t.Fatalf("日志应只记无法解密的 credential id: %s", logBuf.String())
	}

	byTask, bySkipped, taskRaw := doListCredentials(t, s.intranetListCredentials, "/api/credentials?task_id=980041")
	if len(byTask) != 1 || bySkipped != 0 {
		t.Fatalf("按 task 过滤应只返回可解行且 skipped=0: items=%v skipped=%d", byTask, bySkipped)
	}
	assertNoSecretMaterial(t, taskRaw, "")

	onlyBad, onlySkipped, onlyRaw := doListCredentials(t, s.intranetListCredentials, "/api/credentials?task_id=980042")
	if onlySkipped != 1 {
		t.Fatalf("仅有不可解行的任务应 200 且 skipped=1, got %d body=%s", onlySkipped, onlyRaw)
	}
	if len(onlyBad) != 1 {
		t.Fatalf("仅有不可解行的任务 items 应有一条占位: %v", onlyBad)
	}
	m, _ := onlyBad[0].(map[string]any)
	assertUndecryptablePlaceholder(t, m, bid, onlyRaw)
	assertNoSecretMaterial(t, onlyRaw, logBuf.String())
}

func TestCredentialReusePlanEmptyVsUndecryptable(t *testing.T) {
	pg := openIntranetTestDB(t)
	goodKey := []byte("intranet-test-master-key")
	cs := db.NewCredentialStore(pg, goodKey)
	other := db.NewCredentialStore(pg, []byte("another-master-key-32bytes!!!!"))
	s := &Server{credStore: cs, m: &Manager{pg: pg}}

	emptyCtx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 980081})
	emptyRes, err := s.credentialReusePlanTool().Call(emptyCtx, json.RawMessage(`{}`), &actool.ToolContext{})
	if err != nil || emptyRes.IsError {
		t.Fatalf("0 条登记应成功返回说明: err=%v res=%s", err, emptyRes.Flatten())
	}
	emptyText := emptyRes.Flatten()
	if !strings.Contains(emptyText, "还没有登记凭据") {
		t.Fatalf("真正 0 条登记应保持原语义: %s", emptyText)
	}
	if strings.Contains(emptyText, "无法解密") {
		t.Fatalf("0 条登记不得说成无法解密: %s", emptyText)
	}

	bid, err := other.Create(context.Background(), &db.CredentialRecord{
		TaskID: 980082, Username: "other", CredType: "password",
		Secret: "fixture-other-key", Source: "t",
	})
	if err != nil {
		t.Fatalf("Create other: %v", err)
	}
	t.Cleanup(func() { _ = other.Delete(context.Background(), bid) })

	var logBuf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(prev)

	badCtx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 980082})
	badRes, err := s.credentialReusePlanTool().Call(badCtx, json.RawMessage(`{}`), &actool.ToolContext{})
	if err != nil || badRes.IsError {
		t.Fatalf("全是不可解行时应返回说明而不是工具错误: err=%v res=%s", err, badRes.Flatten())
	}
	badText := badRes.Flatten()
	if strings.Contains(badText, "还没有登记凭据") {
		t.Fatalf("已登记但无法解密时不得说还没有登记凭据: %s", badText)
	}
	if !strings.Contains(badText, "无法解密") || !strings.Contains(badText, "无复用建议") {
		t.Fatalf("应明确是已登记但当前无法解密、因此无复用建议: %s", badText)
	}
	assertNoSecretMaterial(t, []byte(badText), logBuf.String())

	listRes, err := s.listCredentialsTool().Call(badCtx, json.RawMessage(`{}`), &actool.ToolContext{})
	if err != nil || listRes.IsError {
		t.Fatalf("list_credentials: err=%v res=%s", err, listRes.Flatten())
	}
	assertNoSecretMaterial(t, []byte(listRes.Flatten()), logBuf.String())
}
