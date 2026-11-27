package server

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestCanonicalSchemaHashAndSyncBuiltinToolSchema(t *testing.T) {
	h1 := canonicalSchemaHash(json.RawMessage(`{"type":"object","properties":{"b":{"type":"string"},"a":{"type":"integer"}}}`))
	h2 := canonicalSchemaHash(json.RawMessage(`{ "properties": { "a": { "type": "integer" }, "b": { "type": "string" } }, "type": "object" }`))
	if h1 == "" || h1 != h2 {
		t.Fatalf("canonicalSchemaHash must be whitespace/key-order invariant: %q vs %q", h1, h2)
	}

	pg := openIntranetTestDB(t)
	s := &Server{m: &Manager{pg: pg}}
	key := fmt.Sprintf("test_sync_tool_%d", time.Now().UnixNano())
	settingKey := toolSchemaHashSettingPrefix + key
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM tools WHERE key=$1`, key)
		_, _ = pg.Exec(`DELETE FROM settings WHERE key=$1`, settingKey)
	})

	v1Schema := json.RawMessage(`{"type":"object","properties":{"url":{"type":"string"}}}`)
	agents := json.RawMessage(`["worker","auto"]`)
	if err := pg.SeedTool(key, "desc v1", v1Schema, agents); err != nil {
		t.Fatalf("SeedTool: %v", err)
	}
	// Disable tool to confirm sync preserves enabled=false and custom agents binding.
	if err := pg.UpdateTool(key, "desc v1", v1Schema, agents, false); err != nil {
		t.Fatalf("UpdateTool disable: %v", err)
	}

	// First sync on unchanged schema records baseline hash without rewriting.
	if changed := s.syncBuiltinToolSchema(key, "desc v1", v1Schema); changed {
		t.Fatal("unchanged schema should not trigger update")
	}
	savedHash, ok, err := pg.GetSetting(settingKey)
	if err != nil || !ok || savedHash != canonicalSchemaHash(v1Schema) {
		t.Fatalf("baseline hash not recorded: hash=%q ok=%v err=%v", savedHash, ok, err)
	}

	// Code schema evolves to v2 while DB still matches baseline hash -> auto-syncs!
	v2Schema := json.RawMessage(`{"type":"object","properties":{"url":{"type":"string"},"method":{"type":"string"}}}`)
	if changed := s.syncBuiltinToolSchema(key, "desc v2", v2Schema); !changed {
		t.Fatal("code schema change should auto-sync into unedited DB row")
	}
	row, err := pg.GetTool(key)
	if err != nil || row == nil {
		t.Fatalf("GetTool after sync: %v", err)
	}
	if row.Description != "desc v2" || canonicalSchemaHash(row.Schema) != canonicalSchemaHash(v2Schema) {
		t.Fatalf("synced row mismatch: desc=%q schema=%s", row.Description, row.Schema)
	}
	if row.Enabled || len(row.Agents) != 2 {
		t.Fatalf("sync must preserve enabled=false and agents=[worker,auto], got enabled=%v agents=%v", row.Enabled, row.Agents)
	}

	// Admin manually edits schema in DB -> subsequent code schema v3 must preserve manual edit!
	adminSchema := json.RawMessage(`{"type":"object","properties":{"url":{"type":"string","default":"https://custom"}}}`)
	if err := pg.UpdateTool(key, "admin custom desc", adminSchema, agents, false); err != nil {
		t.Fatalf("admin UpdateTool: %v", err)
	}
	v3Schema := json.RawMessage(`{"type":"object","properties":{"url":{"type":"string"},"method":{"type":"string"},"extra":{"type":"boolean"}}}`)
	if changed := s.syncBuiltinToolSchema(key, "desc v3", v3Schema); changed {
		t.Fatal("manual admin edit must not be overwritten by code schema sync")
	}
	row2, _ := pg.GetTool(key)
	if row2 == nil || row2.Description != "admin custom desc" || canonicalSchemaHash(row2.Schema) != canonicalSchemaHash(adminSchema) {
		t.Fatalf("admin edit was overwritten: %+v", row2)
	}
}
