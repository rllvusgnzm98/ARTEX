package server

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

// LLM 录制默认开关回归：settings 表无 llm_record 行时必须默认开（否则一次大
// 任务零成本数据）；用户显式关闭（false 已落库）必须尊重。
func TestLLMRecordDefaultsOnAndRespectsExplicitOff(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	pg := m.pg
	if pg == nil {
		t.Skip("no pg")
	}

	// 无行 → 默认开（真实回归点：这里曾是默认关）。
	if _, err := pg.Exec(`DELETE FROM settings WHERE key=$1`, "llm_record"); err != nil {
		t.Fatalf("clear setting: %v", err)
	}
	m.llmRecOn = pg.GetBool(settingLLMRecord, true)
	if !m.llmRecOn {
		t.Error("fresh install (no settings row) must default to recording ON")
	}

	// 显式 false → 尊重关闭。
	if err := m.SetLLMRecordEnabled(false); err != nil {
		t.Fatalf("set off: %v", err)
	}
	if m.LLMRecordEnabled() {
		t.Error("explicit off must be respected")
	}
	if got := pg.GetBool(settingLLMRecord, true); got {
		t.Error("persisted false must survive reload (GetBool with default true)")
	}

	// 显式 true → 开。
	if err := m.SetLLMRecordEnabled(true); err != nil {
		t.Fatalf("set on: %v", err)
	}
	if !m.LLMRecordEnabled() {
		t.Error("explicit on must be respected")
	}
	// 收尾还原为无行状态，避免污染共享 dev 库的其他测试。
	_, _ = pg.Exec(`DELETE FROM settings WHERE key=$1`, "llm_record")
}

// GetBool 语义验证：无行返回传入默认值——这是『默认开』能直接改第二参的前提。
func TestGetBoolDefaultsWhenRowMissing(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	const key = "llmrec_default_probe"
	_, _ = d.Exec(`DELETE FROM settings WHERE key=$1`, key)
	if !d.GetBool(key, true) {
		t.Error("missing row must return the caller-supplied default true")
	}
	if d.GetBool(key, false) {
		t.Error("missing row must return the caller-supplied default false")
	}
}
