package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPostgresDSNPrecedence(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, []byte(`{"database":{"host":"10.1.2.3","port":6000,"user":"u","password":"p","dbname":"d","sslmode":"require"}}`), 0o644)
	t.Setenv("ARTEX_CONFIG", cfgPath)

	// no env DSN → built from config file fields
	t.Setenv("ARTEX_PG_DSN", "")
	got, _, err := PostgresDSN()
	want := "postgres://u:p@10.1.2.3:6000/d?sslmode=require"
	if err != nil || got != want {
		t.Fatalf("from file: got %q err %v want %q", got, err, want)
	}

	// env wins over config file
	t.Setenv("ARTEX_PG_DSN", "postgres://envwins/x")
	if got, _, err := PostgresDSN(); err != nil || got != "postgres://envwins/x" {
		t.Fatalf("env should win, got %q err %v", got, err)
	}

	// no env, no file → error (no built-in default)
	t.Setenv("ARTEX_PG_DSN", "")
	t.Setenv("ARTEX_CONFIG", filepath.Join(dir, "nope.json"))
	if got, _, err := PostgresDSN(); err == nil {
		t.Fatalf("missing config should error, got %q", got)
	}

	// full dsn in config file is used verbatim
	os.WriteFile(cfgPath, []byte(`{"database":{"dsn":"postgres://full/dsn"}}`), 0o644)
	t.Setenv("ARTEX_CONFIG", cfgPath)
	if got, _, err := PostgresDSN(); err != nil || got != "postgres://full/dsn" {
		t.Fatalf("file dsn verbatim, got %q err %v", got, err)
	}
}

func TestRedactMasksURLPassword(t *testing.T) {
	const fake = "s3cret"
	got := Redact("postgres://artex:" + fake + "@127.0.0.1:5432/artex?sslmode=disable")
	if strings.Contains(got, fake) {
		t.Fatalf("URL 形态脱敏后不得出现假口令: %s", got)
	}
	// url.UserPassword 会把 **** 编成 %2A%2A%2A%2A，这是原有 URL 逻辑，保持。
	if !strings.Contains(got, "****") && !strings.Contains(got, "%2A%2A%2A%2A") {
		t.Fatalf("URL 形态应打码口令: %s", got)
	}
}

func TestRedactMasksKeywordPassword(t *testing.T) {
	const fake = "s3cret"
	in := "host=127.0.0.1 user=artex password=" + fake + " dbname=artex"
	got := Redact(in)
	if strings.Contains(got, fake) {
		t.Fatalf("key=value 脱敏后不得出现假口令: %s", got)
	}
	if !strings.Contains(got, "password=****") {
		t.Fatalf("password=s3cret 应变为 password=****, got %s", got)
	}

	for _, key := range []string{"pwd", "pass", "passwd"} {
		in := "host=127.0.0.1 " + key + "=" + fake + " dbname=artex"
		got := Redact(in)
		if strings.Contains(got, fake) {
			t.Fatalf("%s= 脱敏后不得出现假口令: %s", key, got)
		}
		if !strings.Contains(got, key+"=****") {
			t.Fatalf("%s= 应打码, got %s", key, got)
		}
	}
}
