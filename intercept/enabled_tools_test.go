package intercept

import (
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func defaultEnabledSet() map[string]bool {
	m := make(map[string]bool, len(defaultEnabledTools))
	for _, n := range defaultEnabledTools {
		m[n] = true
	}
	return m
}

// TestDefaultEnabledToolsIncludeSessionTools 无已保存设置时，硬编码默认清单
// 必须包含 register_session 与 session_recon。这是 GetEnabledTools 在
// intercept_enabled_tools 从未写入时的回落来源；本用例不碰数据库。
func TestDefaultEnabledToolsIncludeSessionTools(t *testing.T) {
	got := defaultEnabledSet()
	for _, want := range []string{"register_session", "session_recon"} {
		if !got[want] {
			t.Errorf("无已保存设置时，默认拦截工具清单应包含 %s，实际 %v", want, defaultEnabledTools)
		}
	}
}

func openInterceptTestDB(t *testing.T) *db.DB {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// TestGetEnabledToolsUsesDefaultsOnlyWhenUnset 未保存设置时返回默认清单
// （含会话两工具）；已保存的用户清单不得被默默改写或补入新默认项。
func TestGetEnabledToolsUsesDefaultsOnlyWhenUnset(t *testing.T) {
	d := openInterceptTestDB(t)
	ic := New(d)
	const key = "intercept_enabled_tools"

	prev, had, err := d.GetSetting(key)
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	t.Cleanup(func() {
		if had {
			_ = d.SetSetting(key, prev)
		} else {
			_, _ = d.Exec(`DELETE FROM settings WHERE key=$1`, key)
		}
		ic.Invalidate()
	})
	if _, err := d.Exec(`DELETE FROM settings WHERE key=$1`, key); err != nil {
		t.Fatalf("clear setting: %v", err)
	}
	ic.Invalidate()

	tools, err := ic.GetEnabledTools()
	if err != nil {
		t.Fatalf("GetEnabledTools: %v", err)
	}
	got := map[string]bool{}
	for _, n := range tools {
		got[n] = true
	}
	for _, want := range []string{"register_session", "session_recon"} {
		if !got[want] {
			t.Errorf("无已保存设置时 GetEnabledTools 应含 %s，实际 %v", want, tools)
		}
	}
	if !ic.IsToolEnabled("register_session") || !ic.IsToolEnabled("session_recon") {
		t.Errorf("无已保存设置时 IsToolEnabled 应对会话工具为 true")
	}

	// 已保存清单缺少这两项时，必须原样返回，不得悄悄并入新默认值。
	saved := []string{"Bash", "Write"}
	if err := ic.SetEnabledTools(saved); err != nil {
		t.Fatalf("SetEnabledTools: %v", err)
	}
	gotList, err := ic.GetEnabledTools()
	if err != nil {
		t.Fatalf("GetEnabledTools after save: %v", err)
	}
	if len(gotList) != 2 || gotList[0] != "Bash" || gotList[1] != "Write" {
		t.Fatalf("已保存设置不得被默默改写: %v", gotList)
	}
	if ic.IsToolEnabled("register_session") || ic.IsToolEnabled("session_recon") {
		t.Fatalf("已保存清单未包含会话工具时，不应因新默认值被启用")
	}

	raw, ok, err := d.GetSetting(key)
	if err != nil || !ok {
		t.Fatalf("saved setting missing: ok=%v err=%v", ok, err)
	}
	var persisted []string
	if err := json.Unmarshal([]byte(raw), &persisted); err != nil {
		t.Fatalf("saved setting json: %v", err)
	}
	if len(persisted) != 2 || persisted[0] != "Bash" || persisted[1] != "Write" {
		t.Fatalf("库中已保存清单被改写: %v", persisted)
	}
}
