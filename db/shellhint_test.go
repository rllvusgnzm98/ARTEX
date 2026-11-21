package db

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustAgents(t *testing.T, agents []string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(agents)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSeedShellHintNewAndExistingDB(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})

	// Isolate catalog-shaped keys plus a user row so this test does not depend
	// on leftover data. Cleanup deletes only the keys we touch.
	userKey := "t-shellhint-user-custom"
	catalog := []string{"t-shellhint-ffuf", "t-shellhint-nmap", "t-shellhint-sqlmap"}
	cleanup := append([]string{userKey, "t-shellhint-nonshell", "t-shellhint-edited"}, catalog...)
	t.Cleanup(func() {
		for _, k := range cleanup {
			if _, err := d.Exec(`DELETE FROM tools WHERE key=$1`, k); err != nil {
				t.Errorf("cleanup: %v", err)
			}
		}
	})
	for _, k := range cleanup {
		if _, err := d.Exec(`DELETE FROM tools WHERE key=$1`, k); err != nil {
			t.Fatal(err)
		}
	}

	// User-defined row that must survive seeding of catalog keys.
	if err := d.CreateCustomTool(&Tool{
		Key: userKey, Description: "keep me", Kind: "shell",
		Agents: []string{"worker"}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	agents := mustAgents(t, []string{"worker", "pentest"})
	for _, key := range catalog {
		if err := d.SeedShellHint(key, "desc-"+key, agents); err != nil {
			t.Fatalf("seed %s: %v", key, err)
		}
	}

	for _, key := range catalog {
		row, err := d.GetTool(key)
		if err != nil || row == nil {
			t.Fatalf("catalog key %s missing after seed: %v", key, err)
		}
		if row.Kind != "shell" || row.Deferred || !row.System || !row.Enabled {
			t.Fatalf("%s: kind=%s deferred=%v system=%v enabled=%v", key, row.Kind, row.Deferred, row.System, row.Enabled)
		}
		if !containsStr(row.Agents, "worker") || !containsStr(row.Agents, "pentest") {
			t.Fatalf("%s agents=%v, want worker and pentest", key, row.Agents)
		}
		if row.Description != "desc-"+key {
			t.Fatalf("%s desc=%q", key, row.Description)
		}
	}

	user, err := d.GetTool(userKey)
	if err != nil || user == nil {
		t.Fatalf("user row disappeared: %v", err)
	}
	if user.Description != "keep me" || user.Kind != "shell" || user.System {
		t.Fatalf("user row mutated: %+v", user)
	}

	// Re-seed with a different description: existing catalog rows must not move.
	for _, key := range catalog {
		if err := d.SeedShellHint(key, "CHANGED-"+key, agents); err != nil {
			t.Fatalf("reseed %s: %v", key, err)
		}
		row, err := d.GetTool(key)
		if err != nil || row == nil {
			t.Fatal(err)
		}
		if row.Description != "desc-"+key {
			t.Fatalf("reseed overwrote %s: %q", key, row.Description)
		}
	}
}

func TestSeedShellHintPreservesUserEditsAndForeignKind(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})

	editedKey := "t-shellhint-edited"
	foreignKey := "t-shellhint-nonshell"
	t.Cleanup(func() {
		if _, err := d.Exec(`DELETE FROM tools WHERE key=$1 OR key=$2`, editedKey, foreignKey); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	_, _ = d.Exec(`DELETE FROM tools WHERE key=$1 OR key=$2`, editedKey, foreignKey)

	if err := d.SeedShellHint(editedKey, "original", mustAgents(t, []string{"worker", "pentest"})); err != nil {
		t.Fatal(err)
	}
	if err := d.UpdateTool(editedKey, "user edited desc", json.RawMessage(`{}`), mustAgents(t, []string{"pentest"}), true); err != nil {
		t.Fatal(err)
	}

	if _, err := d.Exec(`
INSERT INTO tools(key, system, description, schema, agents, enabled, kind, deferred)
VALUES ($1, true, 'builtin-shaped', '{}'::jsonb, '["planner"]'::jsonb, true, 'builtin', false)`, foreignKey); err != nil {
		t.Fatal(err)
	}

	if err := d.SeedShellHint(editedKey, "code default", mustAgents(t, []string{"worker", "pentest"})); err != nil {
		t.Fatal(err)
	}
	if err := d.SeedShellHint(foreignKey, "should not apply", mustAgents(t, []string{"worker", "pentest"})); err != nil {
		t.Fatal(err)
	}

	edited, err := d.GetTool(editedKey)
	if err != nil || edited == nil {
		t.Fatal(err)
	}
	if edited.Description != "user edited desc" || !containsStr(edited.Agents, "pentest") || containsStr(edited.Agents, "worker") {
		t.Fatalf("edited row overwritten: desc=%q agents=%v", edited.Description, edited.Agents)
	}
	if edited.Kind != "shell" {
		t.Fatalf("edited kind=%s", edited.Kind)
	}

	foreign, err := d.GetTool(foreignKey)
	if err != nil || foreign == nil {
		t.Fatal(err)
	}
	if foreign.Kind != "builtin" || foreign.Description != "builtin-shaped" || !containsStr(foreign.Agents, "planner") {
		t.Fatalf("non-shell row mutated: kind=%s desc=%q agents=%v", foreign.Kind, foreign.Description, foreign.Agents)
	}
}

func TestUpsertToolForceAndResetShellHint(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})

	key := "t-shellhint-reset"
	foreign := "t-shellhint-reset-builtin"
	t.Cleanup(func() {
		if _, err := d.Exec(`DELETE FROM tools WHERE key=$1 OR key=$2`, key, foreign); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	_, _ = d.Exec(`DELETE FROM tools WHERE key=$1 OR key=$2`, key, foreign)

	if err := d.SeedShellHint(key, "original", mustAgents(t, []string{"worker", "pentest"})); err != nil {
		t.Fatal(err)
	}
	if err := d.UpdateTool(key, "user edited", json.RawMessage(`{}`), mustAgents(t, []string{"worker"}), true); err != nil {
		t.Fatal(err)
	}

	// "恢复默认" via UpsertToolForce must refuse and leave kind=shell + user text.
	err = d.UpsertToolForce(key, "forced builtin default", json.RawMessage(`{}`), mustAgents(t, []string{"planner"}))
	if err == nil || !strings.Contains(err.Error(), "non-builtin") {
		t.Fatalf("UpsertToolForce should refuse shell row, err=%v", err)
	}
	row, err := d.GetTool(key)
	if err != nil || row == nil {
		t.Fatal(err)
	}
	if row.Kind != "shell" || row.Description != "user edited" || containsStr(row.Agents, "planner") {
		t.Fatalf("UpsertToolForce mutated shell row: kind=%s desc=%q agents=%v", row.Kind, row.Description, row.Agents)
	}

	if err := d.ResetShellHint(key, "code default", mustAgents(t, []string{"worker", "pentest"})); err != nil {
		t.Fatal(err)
	}
	row, err = d.GetTool(key)
	if err != nil || row == nil {
		t.Fatal(err)
	}
	if row.Kind != "shell" || row.Deferred || row.Description != "code default" {
		t.Fatalf("ResetShellHint: kind=%s deferred=%v desc=%q", row.Kind, row.Deferred, row.Description)
	}
	if !containsStr(row.Agents, "worker") || !containsStr(row.Agents, "pentest") {
		t.Fatalf("ResetShellHint agents=%v", row.Agents)
	}

	if _, err := d.Exec(`
INSERT INTO tools(key, system, description, schema, agents, enabled, kind, deferred)
VALUES ($1, true, 'leave me', '{}'::jsonb, '["planner"]'::jsonb, true, 'builtin', false)`, foreign); err != nil {
		t.Fatal(err)
	}
	err = d.ResetShellHint(foreign, "nope", mustAgents(t, []string{"worker", "pentest"}))
	if err == nil || !strings.Contains(err.Error(), "kind=builtin") {
		t.Fatalf("ResetShellHint should refuse non-shell row, err=%v", err)
	}
	left, err := d.GetTool(foreign)
	if err != nil || left == nil {
		t.Fatal(err)
	}
	if left.Kind != "builtin" || left.Description != "leave me" {
		t.Fatalf("ResetShellHint mutated foreign kind: %+v", left)
	}
}

func containsStr(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}
