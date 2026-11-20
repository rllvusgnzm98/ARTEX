package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestJWTDurationDefaultsAndParse(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_CONFIG", cfgPath)
	t.Setenv("ARTEX_JWT_TTL", "")
	t.Setenv("ARTEX_JWT_ROTATION_PERIOD", "")
	t.Setenv("ARTEX_JWT_GRACE", "")

	if got := JWTTTL(); got != 168*time.Hour {
		t.Fatalf("default TTL = %s, want 168h", got)
	}
	if got := JWTRotationPeriod(); got != 720*time.Hour {
		t.Fatalf("default rotation = %s, want 720h", got)
	}
	if got := JWTGrace(); got != 24*time.Hour {
		t.Fatalf("default grace = %s, want 24h", got)
	}

	t.Setenv("ARTEX_JWT_TTL", "48h")
	t.Setenv("ARTEX_JWT_ROTATION_PERIOD", "0")
	t.Setenv("ARTEX_JWT_GRACE", "1h")
	if got := JWTTTL(); got != 48*time.Hour {
		t.Fatalf("TTL = %s, want 48h", got)
	}
	if got := JWTRotationPeriod(); got != 0 {
		t.Fatalf("rotation 0 should disable, got %s", got)
	}
	if got := JWTGrace(); got != time.Hour {
		t.Fatalf("grace = %s, want 1h", got)
	}

	// 解析失败回落默认，不采用非法值，也不改用文件里的合法值。
	if err := os.WriteFile(cfgPath, []byte(`{"jwt_ttl":"3h","jwt_rotation_period":"9h","jwt_grace":"2h"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_JWT_TTL", "7d")
	t.Setenv("ARTEX_JWT_ROTATION_PERIOD", "nope")
	t.Setenv("ARTEX_JWT_GRACE", "-1s")
	if got := JWTTTL(); got != 168*time.Hour {
		t.Fatalf("bad TTL should fall back, got %s", got)
	}
	if got := JWTRotationPeriod(); got != 720*time.Hour {
		t.Fatalf("bad rotation should fall back, got %s", got)
	}
	if got := JWTGrace(); got != 24*time.Hour {
		t.Fatalf("bad grace should fall back, got %s", got)
	}

	// 未设置环境变量时采用配置文件。0 对轮换周期合法。
	os.Unsetenv("ARTEX_JWT_TTL")
	os.Unsetenv("ARTEX_JWT_ROTATION_PERIOD")
	os.Unsetenv("ARTEX_JWT_GRACE")
	if got := JWTTTL(); got != 3*time.Hour {
		t.Fatalf("file TTL = %s, want 3h", got)
	}
	if err := os.WriteFile(cfgPath, []byte(`{"jwt_rotation_period":"0s","jwt_grace":"0s"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := JWTRotationPeriod(); got != 0 {
		t.Fatalf("file rotation 0 = %s", got)
	}
	if got := JWTGrace(); got != 0 {
		t.Fatalf("file grace 0 = %s", got)
	}
	// TTL 不允许 0，文件里的 0 回落默认。
	if err := os.WriteFile(cfgPath, []byte(`{"jwt_ttl":"0s"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := JWTTTL(); got != 168*time.Hour {
		t.Fatalf("file TTL 0 should fall back, got %s", got)
	}
}
