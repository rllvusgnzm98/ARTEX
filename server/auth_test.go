package server

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GetSetting 对"键不存在"和"读取出错"的返回值只差一个 error：两种情况 value 都是
// 空串。密码相关的 handler 一旦把 error 当成"还没设置密码"，就会在数据库抖动期间
// 敞开初始化入口——authInit 会放行一个未认证请求去覆盖已有的管理员密码，
// authStatus 则会把前端直接送到 /setup 去照着做这件事。
//
// 这两个测试把 handler 的连接池关掉来制造读取失败，断言两处都 fail closed。
func TestAuthStatusFailsClosedWhenDataSourceUnavailable(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	// 关掉池子，让后续 GetSetting 返回 error 而不是 sql.ErrNoRows。
	if err := m.pg.Close(); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: m}
	w := httptest.NewRecorder()
	s.authStatus(w, httptest.NewRequest("GET", "/api/auth/status", nil))

	if w.Code != 503 {
		t.Fatalf("status=%d want 503 (读失败被当成未初始化会把用户送去 /setup 覆盖密码); body=%s", w.Code, w.Body.String())
	}
	var payload struct {
		Initialized *bool `json:"initialized"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err == nil && payload.Initialized != nil {
		t.Fatalf("读失败时不应回答 initialized，得到 %v", *payload.Initialized)
	}
}

func TestAuthInitFailsClosedWhenDataSourceUnavailable(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	if err := m.pg.Close(); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: m}
	w := httptest.NewRecorder()
	body := strings.NewReader(`{"password":"correct horse battery"}`)
	s.authInit(w, httptest.NewRequest("POST", "/api/auth/init", body))

	if w.Code != 503 {
		t.Fatalf("status=%d want 503 (读失败时放行会让未认证请求覆盖已有密码); body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "token") {
		t.Fatalf("读失败时不应签发 token: %s", w.Body.String())
	}
}

func TestValidatePassword(t *testing.T) {
	for _, tc := range []struct {
		name, pw string
		wantErr  bool
	}{
		{"空", "", true},
		{"七位", "1234567", true},
		{"八位", "12345678", false},
		{"八个汉字按字符数而非字节数计", "密码密码密码密码", false},
		{"三个汉字够 9 字节但只有 3 个字符", "密码强", true},
		{"72 字节", strings.Repeat("a", 72), false},
		{"73 字节超出 bcrypt 上限", strings.Repeat("a", 73), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validatePassword(tc.pw); (got != "") != tc.wantErr {
				t.Fatalf("validatePassword(%q)=%q, wantErr=%v", tc.pw, got, tc.wantErr)
			}
		})
	}
}

// /api/auth/init 不经 requireAuth，没有初始化令牌时任何能连上端口的人都能抢先
// 设置管理员密码。这里在真实库上走完整流程：无令牌/错令牌必须 403 且不落库，
// 正确令牌成功后令牌作废、文件删除。
func TestAuthInitRequiresSetupToken(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	if hash, _, err := m.pg.GetSetting(authPassKey); err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	} else if hash != "" {
		t.Skip("开发库已设置管理员密码，跳过以免改动它")
	}
	defer func() { _, _ = m.pg.Exec(`DELETE FROM settings WHERE key=$1`, authPassKey) }()

	keyDir := t.TempDir()
	s := &Server{m: m, jwtKey: []byte(strings.Repeat("k", 32))}
	s.initSetupToken(keyDir)
	tokPath := filepath.Join(keyDir, setupTokenFilename)
	raw, err := os.ReadFile(tokPath)
	if err != nil {
		t.Fatalf("未设置密码时应生成 %s: %v", setupTokenFilename, err)
	}
	setupTok := strings.TrimSpace(string(raw))

	post := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/auth/init", strings.NewReader(body))
		req.RemoteAddr = "203.0.113.7:4444"
		s.authInit(w, req)
		return w
	}
	for name, body := range map[string]string{
		"无令牌": `{"password":"correct horse battery"}`,
		"错令牌": `{"password":"correct horse battery","setup_token":"deadbeef"}`,
	} {
		if w := post(body); w.Code != 403 || strings.Contains(w.Body.String(), `"token"`) {
			t.Fatalf("%s: status=%d body=%s, want 403 无 token", name, w.Code, w.Body.String())
		}
		if hash, _, _ := m.pg.GetSetting(authPassKey); hash != "" {
			t.Fatalf("%s: 被拒绝的请求不应写入密码", name)
		}
	}

	w := post(`{"password":"correct horse battery","setup_token":"` + setupTok + `"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"token"`) {
		t.Fatalf("正确令牌应成功: status=%d body=%s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(tokPath); !os.IsNotExist(err) {
		t.Fatalf("成功初始化后应删除 %s", setupTokenFilename)
	}
	if s.checkSetupToken(setupTok) {
		t.Fatal("令牌用过后应作废")
	}
}

func TestCheckSetupTokenFailsClosedWithoutServerToken(t *testing.T) {
	s := &Server{}
	if s.checkSetupToken("") || s.checkSetupToken("anything") {
		t.Fatal("服务端没有令牌时必须拒绝")
	}
}
