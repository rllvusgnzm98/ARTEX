package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/session"
)

const handoffFixtureSecret = "fixture-pass"

type handoffCredEnv struct {
	t      *testing.T
	m      *Manager
	s      *Server
	cs     *db.CredentialStore
	parent int64
	sess   int64
	child  int64
}

func startHandoffCreds(t *testing.T, host string) *handoffCredEnv {
	t.Helper()
	t.Setenv(inheritUnverifiedEnv, "")
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { m.Close() })
	parent, err := m.CreateTaskWithOptions("handoff cred "+host, "fixture", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	env := &handoffCredEnv{t: t, m: m, parent: mustTaskID(t, parent.ID)}
	t.Cleanup(func() {
		if env.child > 0 {
			_ = m.PG().DeleteTask(env.child)
		}
		_ = m.PG().DeleteTask(env.parent)
	})
	ss := db.NewSessionStore(m.PG(), []byte("intranet-test-master-key"))
	sessID, err := ss.Create(context.Background(), &db.SessionRecord{
		Kind: "http_php", URL: "http://" + host + "/fixture.php", Lang: "php",
		Status: db.SessionAlive, CreatedByTask: env.parent,
	})
	if err != nil {
		t.Fatal(err)
	}
	env.sess = sessID
	t.Cleanup(func() { _ = ss.Delete(context.Background(), sessID) })
	env.cs = db.NewCredentialStore(m.PG(), []byte("intranet-test-master-key"))
	env.s = &Server{m: m, sessStore: ss, sessReg: session.NewRegistry(), credStore: env.cs}
	return env
}

func (e *handoffCredEnv) ipAsset(ip string) int64 {
	e.t.Helper()
	id, err := e.m.Assets().UpsertIP(db.UpsertIPReq{IP: ip, TaskID: e.parent})
	if err != nil {
		e.t.Fatalf("upsert %s: %v", ip, err)
	}
	e.t.Cleanup(func() { _, _ = e.m.PG().Exec(`DELETE FROM assets WHERE id=$1`, id) })
	return id
}

func (e *handoffCredEnv) cred(rec *db.CredentialRecord) int64 {
	e.t.Helper()
	if rec.TaskID == 0 {
		rec.TaskID = e.parent
	}
	if rec.Source == "" {
		rec.Source = "fixture"
	}
	if rec.CredType == "" {
		rec.CredType = db.CredPassword
	}
	if rec.Secret == "" {
		rec.Secret = handoffFixtureSecret
	}
	id, err := e.cs.Create(context.Background(), rec)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = e.cs.Delete(context.Background(), id) })
	return id
}

func (e *handoffCredEnv) handoff() (int, string) {
	e.t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/sessions/"+itoa(e.sess)+"/handoff", nil)
	req.SetPathValue("id", itoa(e.sess))
	w := httptest.NewRecorder()
	e.s.sessionHandoff(w, req)
	if w.Code != http.StatusOK {
		e.t.Fatalf("handoff 状态码=%d body=%s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		e.t.Fatal(err)
	}
	taskID, _ := body["task_id"].(string)
	if taskID == "" {
		e.t.Fatalf("应返回 task_id: %s", w.Body.String())
	}
	n, ok := body["credentials_inherited"].(float64)
	if !ok {
		e.t.Fatalf("响应缺少 credentials_inherited: %s", w.Body.String())
	}
	e.child = mustTaskID(e.t, taskID)
	return int(n), taskID
}

func (e *handoffCredEnv) inheritedByID() map[int64]*db.CredentialRecord {
	e.t.Helper()
	list, err := e.cs.ListInherited(context.Background(), e.child)
	if err != nil {
		e.t.Fatal(err)
	}
	out := map[int64]*db.CredentialRecord{}
	for _, item := range list.Items {
		if item.Inherited {
			out[item.ID] = item
		}
	}
	return out
}

func TestHandoffInheritsVerifiedCredentials(t *testing.T) {
	env := startHandoffCreds(t, "203.0.113.10")
	host := env.ipAsset("203.0.113.10")
	verified := env.cred(&db.CredentialRecord{
		Username: "fixture-admin", CredType: db.CredPassword, Secret: handoffFixtureSecret,
		Verified: true, HostAssetID: host,
	})
	verifiedHash := env.cred(&db.CredentialRecord{
		Username: "fixture-hash", CredType: db.CredHashNT, Secret: "11223344556677889900aabbccddeeff",
		Verified: true, HostAssetID: host,
	})
	unverifiedHash := env.cred(&db.CredentialRecord{
		Username: "fixture-hash-raw", CredType: db.CredHashNT, Secret: "00112233445566778899aabbccddeeff",
		HostAssetID: host,
	})
	unverifiedPass := env.cred(&db.CredentialRecord{
		Username: "fixture-unverified", Secret: "fixture-unverified-secret", HostAssetID: host,
	})

	other, err := env.m.CreateTaskWithOptions("handoff foreign", "fixture", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	otherID := mustTaskID(t, other.ID)
	t.Cleanup(func() { _ = env.m.PG().DeleteTask(otherID) })
	foreign := env.cred(&db.CredentialRecord{
		TaskID: otherID, Username: "foreign", Verified: true, HostAssetID: host,
		Secret: "foreign-fixture-secret",
	})
	if err := env.cs.Inherit(context.Background(), db.CredentialInheritance{
		ChildTaskID: env.parent, SourceTaskID: otherID, CredentialID: foreign,
		ScopeBasis: db.InheritFootholdHost, Score: 140, Reason: "already inherited",
	}); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	n, _ := env.handoff()
	if n != 2 {
		t.Fatalf("credentials_inherited = %d, 应只收 2 条已验证凭据", n)
	}
	got := env.inheritedByID()
	if got[verified] == nil || !got[verified].Inherited || got[verified].SourceTaskID != env.parent ||
		got[verified].ScopeBasis != db.InheritFootholdHost || got[verified].Secret != handoffFixtureSecret {
		t.Fatalf("已验证口令未按立足点继承: %+v", got[verified])
	}
	if got[verifiedHash] == nil || got[verifiedHash].ScopeBasis != db.InheritFootholdHost {
		t.Fatalf("已验证 hash 也应继承: %+v", got[verifiedHash])
	}
	if got[unverifiedHash] != nil || got[unverifiedPass] != nil || got[foreign] != nil {
		t.Fatalf("未验证凭据和父任务上的再继承凭据不应进入子任务: %+v", got)
	}
	logs := buf.String()
	for _, secret := range []string{handoffFixtureSecret, "foreign-fixture-secret", "fixture-unverified-secret"} {
		if strings.Contains(logs, secret) {
			t.Fatalf("移交日志不得含口令: %s", logs)
		}
	}
}

func TestHandoffInheritUnverifiedHashNT(t *testing.T) {
	env := startHandoffCreds(t, "203.0.113.20")
	t.Setenv(inheritUnverifiedEnv, "1")
	host := env.ipAsset("203.0.113.20")
	verified := env.cred(&db.CredentialRecord{
		Username: "fixture-admin", Verified: true, HostAssetID: host, Secret: handoffFixtureSecret,
	})
	hashID := env.cred(&db.CredentialRecord{
		Username: "fixture-hash", CredType: db.CredHashNT, Secret: "11223344556677889900aabbccddeeff",
		HostAssetID: host,
	})
	passID := env.cred(&db.CredentialRecord{
		Username: "fixture-unverified", Secret: "fixture-unverified-secret", HostAssetID: host,
	})
	n, _ := env.handoff()
	if n != 2 {
		t.Fatalf("credentials_inherited = %d, 应是已验证口令 + 未验证 hash_nt", n)
	}
	got := env.inheritedByID()
	if got[verified] == nil || got[hashID] == nil {
		t.Fatalf("应继承 verified 与 hash_nt: %+v", got)
	}
	if got[hashID].CredType != db.CredHashNT || got[hashID].ScopeBasis != db.InheritFootholdHost {
		t.Fatalf("hash_nt 继承标记不对: %+v", got[hashID])
	}
	if got[passID] != nil {
		t.Fatal("未验证口令在 ARTEX_INHERIT_UNVERIFIED=1 时仍不继承")
	}
	var verifiedScore, hashScore float64
	if err := env.m.PG().QueryRow(`SELECT score FROM credential_inheritances WHERE child_task_id=$1 AND credential_id=$2`, env.child, verified).Scan(&verifiedScore); err != nil {
		t.Fatal(err)
	}
	if err := env.m.PG().QueryRow(`SELECT score FROM credential_inheritances WHERE child_task_id=$1 AND credential_id=$2`, env.child, hashID).Scan(&hashScore); err != nil {
		t.Fatal(err)
	}
	if verifiedScore <= hashScore {
		t.Fatalf("已验证分数应高于未验证 hash: %v <= %v", verifiedScore, hashScore)
	}
}

func TestHandoffInheritTruncatesAt20(t *testing.T) {
	env := startHandoffCreds(t, "203.0.113.30")
	host := env.ipAsset("203.0.113.30")
	ids := make([]int64, 0, 21)
	for i := 0; i < 21; i++ {
		ids = append(ids, env.cred(&db.CredentialRecord{
			Username: "fixture-user", Verified: true, HostAssetID: host,
			Secret: handoffFixtureSecret,
		}))
	}
	n, _ := env.handoff()
	if n != 20 {
		t.Fatalf("credentials_inherited = %d, 应截断到 20", n)
	}
	got := env.inheritedByID()
	if len(got) != 20 {
		t.Fatalf("ListInherited 继承条数 = %d", len(got))
	}
	// 同分按 credential id 升序保留前 20，丢掉最大的那条。
	var maxID int64
	for _, id := range ids {
		if id > maxID {
			maxID = id
		}
	}
	if got[maxID] != nil {
		t.Fatalf("最高 id %d 应被截掉", maxID)
	}
	for _, id := range ids {
		if id == maxID {
			continue
		}
		if got[id] == nil {
			t.Fatalf("id %d 应被继承", id)
		}
	}
}

func TestHandoffInheritFailureStillReturnsTask(t *testing.T) {
	env := startHandoffCreds(t, "203.0.113.40")
	host := env.ipAsset("203.0.113.40")
	env.cred(&db.CredentialRecord{
		Username: "fixture-admin", Verified: true, HostAssetID: host, Secret: handoffFixtureSecret,
	})
	raw, err := sql.Open("pgx", "postgres://127.0.0.1:1/inherit_closed?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	raw.Close()
	env.s.credStore = db.NewCredentialStore(&db.DB{DB: raw}, []byte("intranet-test-master-key"))

	n, taskID := env.handoff()
	if n != 0 {
		t.Fatalf("继承失败时 credentials_inherited 应为 0, got %d", n)
	}
	if _, ok := env.m.Task(taskID); !ok {
		t.Fatalf("继承失败不应丢掉已创建的子任务 %s", taskID)
	}
}

func TestHandoffInheritBasisOrder(t *testing.T) {
	env := startHandoffCreds(t, "203.0.113.50")
	foot := env.ipAsset("203.0.113.50")
	if _, err := env.m.PG().Exec(`UPDATE assets SET domain=$2 WHERE id=$1`, foot, "fixture.example"); err != nil {
		t.Fatal(err)
	}
	seg := env.ipAsset("203.0.113.51")
	domHost := env.ipAsset("198.51.100.10")
	coHost := env.ipAsset("198.51.100.20")
	noneHost := env.ipAsset("198.51.100.30")

	cid, err := env.m.PG().Companies().UpsertByName("inherit-fixture-203011350")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.m.PG().Companies().DeleteCompany(cid) })
	if _, err := env.m.PG().Exec(`
INSERT INTO task_scope(task_id, kind, company_id, source, reason)
VALUES ($1, 'company', $2, 'manual', 'fixture')`, env.parent, cid); err != nil {
		t.Fatal(err)
	}
	if _, err := env.m.PG().Exec(`UPDATE assets SET company_id=$2, company_source='explicit' WHERE id=$1`, coHost, cid); err != nil {
		t.Fatal(err)
	}

	ids := map[string]int64{
		db.InheritFootholdHost: env.cred(&db.CredentialRecord{Username: "foot", Verified: true, HostAssetID: foot}),
		db.InheritSameSegment:  env.cred(&db.CredentialRecord{Username: "seg", Verified: true, HostAssetID: seg}),
		db.InheritDomain:       env.cred(&db.CredentialRecord{Username: "dom", Verified: true, HostAssetID: domHost, Domain: "Fixture.Example"}),
		db.InheritCompany:      env.cred(&db.CredentialRecord{Username: "co", Verified: true, HostAssetID: coHost, Domain: "other.example"}),
	}
	none := env.cred(&db.CredentialRecord{Username: "none", Verified: true, HostAssetID: noneHost, Domain: "no-match.example"})

	n, _ := env.handoff()
	if n != 4 {
		t.Fatalf("credentials_inherited = %d, 应是 4 条相关凭据", n)
	}
	got := env.inheritedByID()
	if got[none] != nil {
		t.Fatal("不同主机、不同网段、不同域、不同企业的凭据不应继承")
	}
	var prev float64 = 1e9
	order := []string{db.InheritFootholdHost, db.InheritSameSegment, db.InheritDomain, db.InheritCompany}
	for _, basis := range order {
		item := got[ids[basis]]
		if item == nil || item.ScopeBasis != basis || item.SourceTaskID != env.parent || !item.Inherited {
			t.Fatalf("%s 继承结果不对: %+v", basis, item)
		}
		var score float64
		if err := env.m.PG().QueryRow(`SELECT score FROM credential_inheritances WHERE child_task_id=$1 AND credential_id=$2`, env.child, ids[basis]).Scan(&score); err != nil {
			t.Fatal(err)
		}
		if score >= prev {
			t.Fatalf("%s 分数 %v 应低于更精确的上一条 %v", basis, score, prev)
		}
		prev = score
	}
}

func TestHandoffSelectInheritedRanking(t *testing.T) {
	foot := &db.Asset{ID: 1, IP: "203.0.113.50"}
	seg := &db.Asset{ID: 2, IP: "203.0.113.80"}
	far := &db.Asset{ID: 3, IP: "198.51.100.10", CompanyID: ptrInt64(9)}
	hosts := map[int64]*db.Asset{1: foot, 2: seg, 3: far}
	companies := map[int64]struct{}{9: {}}
	creds := []*db.CredentialRecord{
		{ID: 1, Verified: true, HostAssetID: 1, CredType: db.CredPassword},
		{ID: 2, Verified: false, HostAssetID: 1, CredType: db.CredHashNT},
		{ID: 3, Verified: false, HostAssetID: 1, CredType: db.CredPassword},
		{ID: 4, Verified: true, HostAssetID: 2, CredType: db.CredPassword},
		{ID: 5, Verified: true, HostAssetID: 3, Domain: "Fixture.Example", CredType: db.CredPassword},
		{ID: 6, Verified: true, HostAssetID: 3, Domain: "no-match.example", CredType: db.CredPassword},
		{ID: 7, Verified: true, Domain: "other.example", CredType: db.CredPassword},
	}
	if credEligible(creds[1], false) || credEligible(creds[2], true) {
		t.Fatal("默认不收未验证凭据；开关只额外收 hash_nt，不收未验证口令")
	}
	if !credEligible(creds[1], true) || !credEligible(creds[0], false) {
		t.Fatal("已验证凭据始终可收；开关打开时未验证 hash_nt 可收")
	}
	got := selectInherited(eligibleCreds(creds, false), hosts, "203.0.113.50", "fixture.example", companies)
	if len(got) != 4 {
		t.Fatalf("默认只收已验证且相关的凭据, got %d (%v)", len(got), basesOf(got))
	}
	// id 5 的主机在别的 /24，域与立足点资产相同，所以是 domain 而不是 company。
	// id 6 域不同，落到同企业。id 1 是立足点主机。id 4 是同网段。
	want := []string{db.InheritFootholdHost, db.InheritSameSegment, db.InheritDomain, db.InheritCompany}
	if strings.Join(basesOf(got), ",") != strings.Join(want, ",") {
		t.Fatalf("排序应按 verified 后的精确度, got %v", basesOf(got))
	}
	if got[0].cred.ID != 1 || got[1].cred.ID != 4 || got[2].cred.ID != 5 || got[3].cred.ID != 6 {
		t.Fatalf("条目顺序不对: %+v", got)
	}
	withHash := selectInherited(eligibleCreds(creds, true), hosts, "203.0.113.50", "fixture.example", companies)
	if len(withHash) != 5 || withHash[4].cred.ID != 2 || withHash[4].score >= got[0].score {
		t.Fatalf("未验证 hash_nt 应排在已验证之后: %+v", basesOf(withHash))
	}

	many := make([]*db.CredentialRecord, 0, 21)
	for i := int64(1); i <= 21; i++ {
		many = append(many, &db.CredentialRecord{ID: i, Verified: true, HostAssetID: 1, CredType: db.CredPassword})
	}
	ranked := selectInherited(many, hosts, "203.0.113.50", "", nil)
	if len(ranked) != 21 {
		t.Fatalf("selectInherited 本身不截断, got %d", len(ranked))
	}
	if ranked[0].cred.ID != 1 || ranked[20].cred.ID != 21 {
		t.Fatalf("同分应按 id 升序: first=%d last=%d", ranked[0].cred.ID, ranked[20].cred.ID)
	}
	if len(ranked[:maxInheritedCreds]) != 20 || ranked[:maxInheritedCreds][19].cred.ID != 20 {
		t.Fatal("截断应丢掉 id 21")
	}
}

func eligibleCreds(creds []*db.CredentialRecord, allowUnverifiedHash bool) []*db.CredentialRecord {
	out := make([]*db.CredentialRecord, 0, len(creds))
	for _, c := range creds {
		if credEligible(c, allowUnverifiedHash) {
			out = append(out, c)
		}
	}
	return out
}

func basesOf(picks []inheritedPick) []string {
	out := make([]string, len(picks))
	for i, p := range picks {
		out[i] = p.basis
	}
	return out
}

func ptrInt64(n int64) *int64 { return &n }
