package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeSkill(t *testing.T, dir, name, desc string) {
	t.Helper()
	d := filepath.Join(dir, name)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "---\nname: " + name + "\ndescription: " + desc + "\n---\nbody\n"
	if err := os.WriteFile(filepath.Join(d, "SKILL.md"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSkillDirCacheReusesAndInvalidates(t *testing.T) {
	dir := t.TempDir()
	writeSkill(t, dir, "alpha", "first")
	var c skillDirCache
	r1, err := c.load(dir)
	if err != nil || len(r1.List()) != 1 {
		t.Fatalf("load: %v %v", r1, err)
	}
	r2, _ := c.load(dir)
	if r2 != r1 {
		t.Fatal("unchanged dir must reuse the cached registry")
	}

	writeSkill(t, dir, "beta", "second")
	r3, _ := c.load(dir)
	if r3 == r1 || len(r3.List()) != 2 {
		t.Fatalf("added skill not picked up: %d", len(r3.List()))
	}

	p := filepath.Join(dir, "alpha", "SKILL.md")
	writeSkill(t, dir, "alpha", "edited description")
	future := time.Now().Add(time.Minute)
	_ = os.Chtimes(p, future, future)
	r4, _ := c.load(dir)
	if r4 == r3 {
		t.Fatal("edited skill not picked up")
	}
	if s, ok := r4.Get("alpha"); !ok || s.Description != "edited description" {
		t.Fatalf("stale skill content: %+v", s)
	}

	_ = os.RemoveAll(filepath.Join(dir, "beta"))
	if r5, _ := c.load(dir); len(r5.List()) != 1 {
		t.Fatal("removed skill still listed")
	}
}
