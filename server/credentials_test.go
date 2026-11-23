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

	"sync"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/session"
	actool "github.com/Autumn-27/norma/tool"
)

// lockedBuf 串行化 log.SetOutput 捕获：Server 的后台 worker 可能与断言并发写。
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

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
	if _, err := m.Assets().AddAgentScope(taskID, "cidr", "10.0.0.0/24", "fixture reuse scope", "manual"); err != nil {
		t.Fatalf("AddAgentScope: %v", err)
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

	var buf lockedBuf
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

	var logBuf lockedBuf
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

	var logBuf lockedBuf
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

func TestCredentialInheritedVisibleToListAndReusePlan(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { m.Close() })

	parent, err := m.CreateTaskWithOptions("inherited cred parent", "fixture", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	child, err := m.CreateTaskWithOptions("inherited cred child", "fixture", db.TaskCreateOptions{
		SourceTaskIDs: []int64{mustTaskID(t, parent.ID)},
	})
	if err != nil {
		t.Fatal(err)
	}
	parentID := mustTaskID(t, parent.ID)
	childID := mustTaskID(t, child.ID)
	t.Cleanup(func() {
		_ = m.PG().DeleteTask(childID)
		_ = m.PG().DeleteTask(parentID)
	})

	srcID, err := m.Assets().UpsertIP(db.UpsertIPReq{IP: "10.9.1.5", TaskID: parentID})
	if err != nil {
		t.Fatalf("UpsertIP src: %v", err)
	}
	if _, err := m.Assets().UpsertIP(db.UpsertIPReq{
		IP: "10.9.1.9", TaskID: parentID,
		OpenPorts: []db.PortService{{Port: 22, Service: "ssh"}},
	}); err != nil {
		t.Fatalf("UpsertIP cand: %v", err)
	}
	t.Cleanup(func() {
		_, _ = m.PG().Exec(`DELETE FROM assets WHERE ip IN ('10.9.1.5','10.9.1.9')`)
	})
	// 子任务只有范围，资产仍记在父任务上。候选必须走范围内查询才能出现。
	if _, err := m.Assets().AddAgentScope(childID, "cidr", "10.9.1.0/24", "child scope only", "manual"); err != nil {
		t.Fatal(err)
	}

	const inheritedSecret = "inherited-plan-secret"
	const ownSecret = "own-plan-secret"
	cs := db.NewCredentialStore(m.PG(), []byte("intranet-test-master-key"))
	inheritedID, err := cs.Create(context.Background(), &db.CredentialRecord{
		TaskID: parentID, Username: "inherited-admin", CredType: db.CredPassword,
		Secret: inheritedSecret, Domain: "FIXTURE", Source: "10.9.1.5 fixture source ssh",
		HostAssetID: srcID,
	})
	if err != nil {
		t.Fatal(err)
	}
	ownID, err := cs.Create(context.Background(), &db.CredentialRecord{
		TaskID: childID, Username: "child-own", CredType: db.CredPassword,
		Secret: ownSecret, Source: "child fixture",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cs.Delete(context.Background(), inheritedID)
		_ = cs.Delete(context.Background(), ownID)
	})
	if err := cs.Inherit(context.Background(), db.CredentialInheritance{
		ChildTaskID: childID, SourceTaskID: parentID, CredentialID: inheritedID,
		ScopeBasis: db.InheritDomain, Score: 120, Reason: "fixture",
	}); err != nil {
		t.Fatal(err)
	}

	s := &Server{credStore: cs, m: m}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: childID})
	listRes, err := s.listCredentialsTool().Call(ctx, json.RawMessage(`{}`), &actool.ToolContext{})
	if err != nil {
		t.Fatal(err)
	}
	listOut := toolResultJSON(t, listRes)
	listRaw, _ := json.Marshal(listOut)
	if strings.Contains(string(listRaw), inheritedSecret) || strings.Contains(string(listRaw), ownSecret) {
		t.Fatalf("list_credentials 不得回显明文: %s", listRaw)
	}
	creds, _ := listOut["credentials"].([]any)
	var sawInherited, sawOwn bool
	for _, item := range creds {
		row, _ := item.(map[string]any)
		id, _ := row["id"].(float64)
		switch int64(id) {
		case inheritedID:
			sawInherited = true
			if row["inherited"] != true {
				t.Fatalf("继承条目 inherited 应为 true: %#v", row)
			}
			src, _ := row["source_task_id"].(float64)
			if int64(src) != parentID || row["scope_basis"] != db.InheritDomain {
				t.Fatalf("继承元数据不符: %#v", row)
			}
			if _, ok := row["secret"]; ok {
				t.Fatalf("列表不得含 secret 字段: %#v", row)
			}
		case ownID:
			sawOwn = true
			if row["inherited"] != false {
				t.Fatalf("自有条目 inherited 应为 false: %#v", row)
			}
		}
	}
	if !sawInherited || !sawOwn {
		t.Fatalf("列表应同时含继承凭据和自有凭据: %s", listRaw)
	}

	planRes, err := s.credentialReusePlanTool().Call(ctx, json.RawMessage(`{}`), &actool.ToolContext{})
	if err != nil {
		t.Fatal(err)
	}
	planOut := toolResultJSON(t, planRes)
	planRaw, _ := json.Marshal(planOut)
	sugs, _ := planOut["suggestions"].([]any)
	var sawPlan bool
	for _, item := range sugs {
		row, _ := item.(map[string]any)
		id, _ := row["cred_id"].(float64)
		if int64(id) != inheritedID {
			continue
		}
		sawPlan = true
		if row["secret"] != inheritedSecret || row["username"] != "inherited-admin" {
			t.Fatalf("复用建议应带继承凭据的必要字段: %#v", row)
		}
	}
	if !sawPlan {
		t.Fatalf("范围内的继承凭据应出现在 credential_reuse_plan: %s", planRaw)
	}
	if strings.Contains(db.RedactCredentialPayload("credential_reuse_plan", string(planRaw)), inheritedSecret) {
		t.Fatalf("活动日志清洗后不得含继承凭据明文: %s", planRaw)
	}
}

func TestCredentialRegisterSessionSetsVerified(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { m.Close() })
	parent, err := m.CreateTaskWithOptions("verify parent", "fixture", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	child, err := m.CreateTaskWithOptions("verify child", "fixture", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := m.CreateTaskWithOptions("verify other", "fixture", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	parentID := mustTaskID(t, parent.ID)
	childID := mustTaskID(t, child.ID)
	otherID := mustTaskID(t, other.ID)
	t.Cleanup(func() {
		// register_session 会往 sessions 表写行；测试用自己的主密钥建库，
		// 残留行会污染后续用别的密钥 List 的用例，必须先清掉。
		for _, tid := range []int64{childID, parentID, otherID} {
			_, _ = m.PG().Exec(`DELETE FROM sessions WHERE created_by_task=$1`, tid)
		}
		_ = m.PG().DeleteTask(childID)
		_ = m.PG().DeleteTask(parentID)
		_ = m.PG().DeleteTask(otherID)
	})
	if _, err := m.Assets().AddAgentScope(childID, "ip", "127.0.0.1", "loopback foothold", "manual"); err != nil {
		t.Fatal(err)
	}

	cs := db.NewCredentialStore(m.PG(), []byte("intranet-test-master-key"))
	ownID, err := cs.Create(context.Background(), &db.CredentialRecord{
		TaskID: childID, Username: "own-user", CredType: db.CredPassword,
		Secret: "own-register-secret", Source: "fixture",
	})
	if err != nil {
		t.Fatal(err)
	}
	inheritedID, err := cs.Create(context.Background(), &db.CredentialRecord{
		TaskID: parentID, Username: "inherited-user", CredType: db.CredPassword,
		Secret: "inherited-register-secret", Source: "fixture",
	})
	if err != nil {
		t.Fatal(err)
	}
	foreignID, err := cs.Create(context.Background(), &db.CredentialRecord{
		TaskID: otherID, Username: "foreign-user", CredType: db.CredPassword,
		Secret: "foreign-register-secret", Source: "fixture",
	})
	if err != nil {
		t.Fatal(err)
	}
	unseenID, err := cs.Create(context.Background(), &db.CredentialRecord{
		TaskID: childID, Username: "unseen-user", CredType: db.CredPassword,
		Secret: "unseen-register-secret", Source: "fixture",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cs.Delete(context.Background(), ownID)
		_ = cs.Delete(context.Background(), inheritedID)
		_ = cs.Delete(context.Background(), foreignID)
		_ = cs.Delete(context.Background(), unseenID)
	})
	if err := cs.Inherit(context.Background(), db.CredentialInheritance{
		ChildTaskID: childID, SourceTaskID: parentID, CredentialID: inheritedID,
		ScopeBasis: db.InheritManual, Score: 5, Reason: "fixture",
	}); err != nil {
		t.Fatal(err)
	}

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		cmd := r.Form.Get("cmd")
		cmd = strings.TrimPrefix(cmd, "echo ")
		cmd = strings.TrimSuffix(strings.TrimSpace(cmd), "2>&1")
		cmd = strings.TrimSpace(cmd)
		cmd = strings.ReplaceAll(cmd, "$((40+2))", "42")
		_, _ = w.Write([]byte(cmd))
	}))
	t.Cleanup(origin.Close)
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(dead.Close)

	ss := db.NewSessionStore(m.PG(), []byte("intranet-test-master-key"))
	s := &Server{
		credStore: cs, m: m,
		sessStore: ss, sessReg: session.NewRegistry(),
	}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: childID})
	tool := s.registerSessionTool()

	register := func(url string, credID int64, extra map[string]any) (map[string]any, actool.Result) {
		t.Helper()
		body := map[string]any{"url": url, "lang": "phpcmd", "verified": true, "note": "模型自称已经验证"}
		if credID > 0 {
			body["credential_id"] = credID
		}
		for k, v := range extra {
			body[k] = v
		}
		raw, _ := json.Marshal(body)
		res, err := tool.Call(ctx, raw, &actool.ToolContext{})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			return nil, res
		}
		return toolResultJSON(t, res), res
	}
	assertVerified := func(id int64, want bool) {
		t.Helper()
		got, err := cs.Get(context.Background(), id)
		if err != nil || got == nil {
			t.Fatalf("读取凭据 %d: %v", id, err)
		}
		if got.Verified != want {
			t.Fatalf("凭据 %d verified=%v, 想要 %v", id, got.Verified, want)
		}
	}

	out, _ := register(origin.URL+"/own.php", ownID, nil)
	if out["credential_verified"] != true || out["credential_warning"] != nil {
		t.Fatalf("本任务凭据应被平台置为已验证: %#v", out)
	}
	if _, ok := out["session_id"]; !ok {
		t.Fatalf("登记应成功: %#v", out)
	}
	assertVerified(ownID, true)
	assertVerified(inheritedID, false)

	out, _ = register(origin.URL+"/inherited.php", inheritedID, nil)
	if out["credential_verified"] != true {
		t.Fatalf("已继承凭据应被平台置为已验证: %#v", out)
	}
	assertVerified(inheritedID, true)

	out, _ = register(origin.URL+"/foreign.php", foreignID, nil)
	if _, ok := out["session_id"]; !ok {
		t.Fatalf("越权 credential_id 不得影响登记成功: %#v", out)
	}
	warn, _ := out["credential_warning"].(string)
	if !strings.Contains(warn, "不属于本任务") || out["credential_verified"] == true {
		t.Fatalf("越权 id 应给出非致命提示且不置位: %#v", out)
	}
	assertVerified(foreignID, false)
	flat, _ := json.Marshal(out)
	if strings.Contains(string(flat), "foreign-register-secret") || strings.Contains(string(flat), "own-register-secret") {
		t.Fatalf("登记结果不得回显凭据明文: %s", flat)
	}

	if _, res := register(dead.URL+"/miss.php", unseenID, nil); !res.IsError {
		t.Fatal("探针失败时应登记失败")
	}
	assertVerified(unseenID, false)
	assertVerified(foreignID, false)
}

func TestCredentialInheritAPIIdempotentRevokeAndNoParent(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { m.Close() })
	parent, err := m.CreateTaskWithOptions("api inherit parent", "fixture", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	parentID := mustTaskID(t, parent.ID)
	bySource, err := m.CreateTaskWithOptions("api inherit by source", "fixture", db.TaskCreateOptions{
		SourceTaskIDs: []int64{parentID},
	})
	if err != nil {
		t.Fatal(err)
	}
	byParent, err := m.CreateTaskWithOptions("api inherit by parent", "fixture", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	lone, err := m.CreateTaskWithOptions("api inherit lone", "fixture", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	sourceChild := mustTaskID(t, bySource.ID)
	parentChild := mustTaskID(t, byParent.ID)
	loneID := mustTaskID(t, lone.ID)
	t.Cleanup(func() {
		_ = m.PG().DeleteTask(sourceChild)
		_ = m.PG().DeleteTask(parentChild)
		_ = m.PG().DeleteTask(loneID)
		_ = m.PG().DeleteTask(parentID)
	})
	if err := m.PG().SetParentRef(parentChild, strconv.FormatInt(parentID, 10)); err != nil {
		t.Fatal(err)
	}

	host, err := m.Assets().UpsertIP(db.UpsertIPReq{IP: "198.51.100.40", TaskID: parentID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.PG().Exec(`DELETE FROM assets WHERE id=$1`, host) })
	for _, id := range []int64{sourceChild, parentChild} {
		if _, err := m.Assets().AddAgentScope(id, "ip", "198.51.100.40", "handoff 立足点", "manual"); err != nil {
			t.Fatal(err)
		}
	}
	cs := db.NewCredentialStore(m.PG(), []byte("intranet-test-master-key"))
	const secret = "inherit-api-secret-value"
	credID, err := cs.Create(context.Background(), &db.CredentialRecord{
		TaskID: parentID, Username: "api-admin", CredType: db.CredPassword,
		Secret: secret, Verified: true, HostAssetID: host, Source: "fixture",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Delete(context.Background(), credID) })
	s := &Server{credStore: cs, m: m}

	post := func(taskID int64) (code int, inherited int, raw string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/tasks/"+strconv.FormatInt(taskID, 10)+"/credentials/inherit", nil)
		req.SetPathValue("id", strconv.FormatInt(taskID, 10))
		w := httptest.NewRecorder()
		s.intranetSyncInheritedCredentials(w, req)
		raw = w.Body.String()
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		n, _ := body["inherited"].(float64)
		return w.Code, int(n), raw
	}
	activeCount := func(taskID int64) int {
		t.Helper()
		var n int
		if err := m.PG().QueryRow(`SELECT count(*) FROM credential_inheritances WHERE child_task_id=$1 AND credential_id=$2 AND state='active'`, taskID, credID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	code, n, raw := post(sourceChild)
	if code != http.StatusOK || n != 1 {
		t.Fatalf("来源任务重同步应继承 1 条: code=%d body=%s", code, raw)
	}
	code, again, raw := post(sourceChild)
	if code != http.StatusOK || again != n {
		t.Fatalf("重同步应幂等: code=%d first=%d second=%d body=%s", code, n, again, raw)
	}
	if got := activeCount(sourceChild); got != 1 {
		t.Fatalf("active 继承行应仍是 1, got %d", got)
	}

	code, n, raw = post(parentChild)
	if code != http.StatusOK || n != 1 {
		t.Fatalf("仅 parent_ref 的子任务应继承 1 条: code=%d body=%s", code, raw)
	}

	items, _, listRaw := doListCredentials(t, s.intranetListCredentials, "/api/credentials?task_id="+strconv.FormatInt(sourceChild, 10))
	if strings.Contains(string(listRaw), secret) {
		t.Fatalf("列表不得含明文: %s", listRaw)
	}
	var saw bool
	for _, item := range items {
		row, _ := item.(map[string]any)
		id, _ := row["id"].(float64)
		if int64(id) != credID {
			continue
		}
		saw = true
		src, _ := row["source_task_id"].(float64)
		if row["inherited"] != true || int64(src) != parentID || row["scope_basis"] == "" {
			t.Fatalf("API 列表应带继承字段: %#v", row)
		}
	}
	if !saw {
		t.Fatalf("撤销前列表应含继承凭据: %s", listRaw)
	}

	del := httptest.NewRequest(http.MethodDelete, "/api/tasks/"+strconv.FormatInt(sourceChild, 10)+"/credentials/inherit/"+strconv.FormatInt(credID, 10), nil)
	del.SetPathValue("id", strconv.FormatInt(sourceChild, 10))
	del.SetPathValue("credID", strconv.FormatInt(credID, 10))
	dw := httptest.NewRecorder()
	s.intranetRevokeInheritedCredential(dw, del)
	if dw.Code != http.StatusOK {
		t.Fatalf("撤销应成功: code=%d body=%s", dw.Code, dw.Body.String())
	}
	items, _, listRaw = doListCredentials(t, s.intranetListCredentials, "/api/credentials?task_id="+strconv.FormatInt(sourceChild, 10))
	for _, item := range items {
		row, _ := item.(map[string]any)
		id, _ := row["id"].(float64)
		if int64(id) == credID {
			t.Fatalf("撤销后列表不应再含该凭据: %s", listRaw)
		}
	}
	dw = httptest.NewRecorder()
	s.intranetRevokeInheritedCredential(dw, del)
	if dw.Code != http.StatusNotFound {
		t.Fatalf("再次撤销应 404: code=%d body=%s", dw.Code, dw.Body.String())
	}

	code, n, raw = post(loneID)
	if code != http.StatusOK || n != 0 {
		t.Fatalf("无父任务应返回 0 而不是错误: code=%d body=%s", code, raw)
	}
	if strings.Contains(raw, "500") {
		t.Fatalf("无父任务响应体不应像 500: %s", raw)
	}
}
