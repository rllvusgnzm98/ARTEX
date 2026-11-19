package db

// credstore_test.go:凭据落库层测试。加解密 roundtrip 不依赖 PG；
// CRUD 走现有 PG-gated skip 模式（无库即跳）。测试只用明显假数据。

import (
	"context"
	"encoding/json"
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
	defer d.Close()
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
