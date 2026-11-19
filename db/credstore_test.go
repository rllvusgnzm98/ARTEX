package db

// credstore_test.go:凭据落库层测试。加解密 roundtrip 不依赖 PG；
// CRUD 走现有 PG-gated skip 模式（无库即跳）。测试只用明显假数据。

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"strconv"
	"strings"
	"testing"
)

const fixturePass = "fixture-pass"

// TestCredentialSecretCrypto 不依赖 PG：AES-GCM roundtrip、与 sessions 的域分离、
// 错密钥失败、未初始化密钥拒绝明文落库、篡改认证失败。
func TestCredentialSecretCrypto(t *testing.T) {
	master := []byte("test-jwt-key-material-32bytes!!!")
	key := CredentialSecretKey(master)
	if len(key) != 32 {
		t.Fatalf("派生密钥长度 = %d", len(key))
	}
	if string(key) == string(SessionSecretKey(master)) {
		t.Fatal("credentials 与 sessions 派生密钥相同,域分离失效")
	}

	store := &CredentialStore{key: key}
	enc, err := store.encrypt(fixturePass)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !strings.HasPrefix(enc, secretPrefix) {
		t.Fatalf("密文缺版本前缀: %q", enc)
	}
	if strings.Contains(enc, fixturePass) {
		t.Fatal("密文不得包含明文片段")
	}
	dec, err := store.decrypt(enc)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if dec != fixturePass {
		t.Fatalf("roundtrip 不一致: %q", dec)
	}
	enc2, _ := store.encrypt(fixturePass)
	if enc == enc2 {
		t.Fatal("nonce 未随机化:两次密文相同")
	}
	wrong := &CredentialStore{key: CredentialSecretKey([]byte("another-master-key-32bytes!!!!"))}
	if _, err := wrong.decrypt(enc); err == nil {
		t.Fatal("错密钥解密应失败")
	}
	cross := &CredentialStore{key: SessionSecretKey(master)}
	if _, err := cross.decrypt(enc); err == nil {
		t.Fatal("sessions 密钥解 credentials 密文应失败(域分离)")
	}
	noKey := &CredentialStore{}
	if _, err := noKey.encrypt("x"); err == nil {
		t.Fatal("密钥未初始化应拒绝加密")
	}
	if _, err := noKey.decrypt(enc); err == nil {
		t.Fatal("密钥未初始化应拒绝解密")
	}
	if _, err := store.decrypt(fixturePass); err == nil {
		t.Fatal("未知格式应拒绝按明文读取")
	}
	tampered := enc[:len(enc)-4] + "AAAA"
	if _, err := store.decrypt(tampered); err == nil {
		t.Fatal("篡改密文应认证失败")
	}
}

func TestMaskSecret(t *testing.T) {
	cases := map[string]string{
		"fixture-pass": "fi****ss",
		"abcdef":       "ab****ef",
		"abcde":        "ab****de",
		"abcd":         "****",
		"a":            "****",
		"":             "****",
	}
	for in, want := range cases {
		if got := MaskSecret(in); got != want {
			t.Errorf("MaskSecret(%q) = %q,期望 %q", in, got, want)
		}
	}
}

func TestPublicCredentialOmitsPlaintext(t *testing.T) {
	c := &CredentialRecord{ID: 1, TaskID: 2, Username: "alice", CredType: CredPassword, Secret: fixturePass, Source: "fixture"}
	item := PublicCredential(c)
	raw, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if strings.Contains(s, fixturePass) || strings.Contains(s, `"secret"`) {
		t.Fatalf("列表视图不得含明文 secret: %s", s)
	}
	if item["secret_masked"] != MaskSecret(fixturePass) {
		t.Fatalf("应含 secret_masked: %#v", item)
	}
}

func TestRedactCredentialPayload(t *testing.T) {
	in := `{"username":"alice","secret":"fixture-pass","cred_type":"password"}`
	got := RedactCredentialPayload("add_credential", in)
	if strings.Contains(got, fixturePass) {
		t.Fatalf("活动日志不得含明文: %s", got)
	}
	if !strings.Contains(got, "alice") {
		t.Fatalf("非敏感字段应保留: %s", got)
	}
	plain := RedactCredentialPayload("Bash", `{"command":"echo fixture-pass"}`)
	if plain != `{"command":"echo fixture-pass"}` {
		t.Fatalf("非凭据工具不得改写: %s", plain)
	}
}

func TestValidCredType(t *testing.T) {
	for _, ty := range []string{"password", "hash_nt", "hash_lm", "hash_sha1", "ticket", "ssh_key", "token"} {
		if !ValidCredType(ty) {
			t.Errorf("%s 应合法", ty)
		}
	}
	for _, ty := range []string{"", "ntlm", "PASSWORD", "key"} {
		if ValidCredType(ty) {
			t.Errorf("%q 不应合法", ty)
		}
	}
}

func TestCredentialStoreCRUD(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	// 关库必须在删行之后：t.Cleanup 后注册先执行，避免 defer Close 抢在 Cleanup Delete 前面。
	t.Cleanup(func() { d.Close() })
	store := NewCredentialStore(d, []byte("test-jwt-key-material-32bytes!!!"))
	ctx := context.Background()

	if _, err := store.Create(ctx, &CredentialRecord{TaskID: 1, CredType: "ntlm", Secret: "x", Source: "t"}); err == nil {
		t.Fatal("非法 cred_type 应报错")
	}
	if _, err := store.Create(ctx, &CredentialRecord{TaskID: 1, CredType: "password", Source: "t"}); err == nil {
		t.Fatal("空 secret 应报错")
	}
	if _, err := store.Create(ctx, &CredentialRecord{CredType: "password", Secret: "x", Source: "t"}); err == nil {
		t.Fatal("缺 task_id 应报错")
	}

	rec := &CredentialRecord{
		TaskID: 999999001, Username: "fixture-admin", CredType: "password",
		Secret: fixturePass, Domain: "FIXTURE",
		Source: "10.0.0.5 fixture source smb",
	}
	id, err := store.Create(ctx, rec)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = store.Delete(context.Background(), id) })

	var raw string
	if err := d.QueryRow(`SELECT secret FROM credentials WHERE id=$1`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, secretPrefix) || strings.Contains(raw, fixturePass) {
		t.Fatalf("落库 secret 应为 gcm1 密文, 不得含明文")
	}

	got, err := store.Get(ctx, id)
	if err != nil || got == nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Secret != rec.Secret || got.Domain != "FIXTURE" || got.Verified {
		t.Fatalf("got = %+v", got)
	}

	other := &CredentialRecord{TaskID: 999999002, CredType: "password", Secret: "fixture-other", Source: "t"}
	oid, err := store.Create(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Delete(context.Background(), oid) })
	list, err := store.ListByTask(ctx, 999999001)
	if err != nil || len(list) != 1 || list[0].ID != id {
		t.Fatalf("ListByTask = %v, %v", list, err)
	}
	// 函数体内删除第二行，避免只靠 Cleanup（若 Close 过早会删失败并留行）。
	if err := store.Delete(ctx, oid); err != nil {
		t.Fatalf("Delete other: %v", err)
	}
	left, err := store.Get(ctx, oid)
	if err != nil || left != nil {
		t.Fatalf("第二行删除后 Get 应为 (nil,nil), got %v, %v", left, err)
	}

	if err := store.SetVerified(ctx, id, true); err != nil {
		t.Fatal(err)
	}
	got, _ = store.Get(ctx, id)
	if !got.Verified {
		t.Fatal("SetVerified 未生效")
	}

	if err := store.Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	got, err = store.Get(ctx, id)
	if err != nil || got != nil {
		t.Fatalf("删除后 Get 应为 (nil,nil), got %v, %v", got, err)
	}
}

func TestListSkipsUndecryptableRows(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { d.Close() })
	ctx := context.Background()
	good := NewCredentialStore(d, []byte("test-jwt-key-material-32bytes!!!"))
	other := NewCredentialStore(d, []byte("another-master-key-32bytes!!!!"))

	gid, err := good.Create(ctx, &CredentialRecord{TaskID: 999999011, Username: "fixture-admin", CredType: "password", Secret: fixturePass, Source: "fixture source"})
	if err != nil {
		t.Fatalf("Create good: %v", err)
	}
	t.Cleanup(func() { _ = good.Delete(context.Background(), gid) })
	bid, err := other.Create(ctx, &CredentialRecord{TaskID: 999999012, Username: "other", CredType: "password", Secret: "fixture-other-key", Source: "t"})
	if err != nil {
		t.Fatalf("Create other: %v", err)
	}
	t.Cleanup(func() { _ = other.Delete(context.Background(), bid) })

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	all, err := good.ListAll(ctx)
	if err != nil {
		t.Fatalf("ListAll 不得因单行解密失败而失败: %v", err)
	}
	foundGood, foundBad := false, false
	for _, r := range all {
		if r.ID == gid {
			foundGood = true
			if r.Secret != fixturePass {
				t.Fatalf("可解行应完整返回: %+v", r)
			}
		}
		if r.ID == bid {
			foundBad = true
		}
	}
	if !foundGood {
		t.Fatal("ListAll 应含可解行")
	}
	if foundBad {
		t.Fatal("ListAll 不得返回无法解密的行")
	}

	same, err := good.ListByTask(ctx, 999999012)
	if err != nil {
		t.Fatalf("ListByTask 不得因单行解密失败而失败: %v", err)
	}
	if len(same) != 0 {
		t.Fatalf("不可解任务列表应跳过该行: %+v", same)
	}

	logs := buf.String()
	if strings.Contains(logs, fixturePass) || strings.Contains(logs, "fixture-other-key") || strings.Contains(logs, secretPrefix) {
		t.Fatalf("跳过日志不得含口令或密文: %s", logs)
	}
	if !strings.Contains(logs, "skip credential") || !strings.Contains(logs, strconv.FormatInt(bid, 10)) {
		t.Fatalf("日志应只记无法解密的 credential id: %s", logs)
	}

	got, err := good.Get(ctx, bid)
	if err == nil || got != nil {
		t.Fatalf("Get(id) 对无法解密的单行仍应返回错误, got %v, %v", got, err)
	}
}
