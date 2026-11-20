package config

import (
	"os"
	"path/filepath"
	"testing"
)

func clearGateEnv(t *testing.T) {
	t.Helper()
	t.Setenv("ARTEX_GATE_MODE", "")
	t.Setenv("ARTEX_GATE", "")
	t.Setenv("ARTEX_CONFIG", filepath.Join(t.TempDir(), "missing-config.json"))
}

func TestResolveGatePriority(t *testing.T) {
	clearGateEnv(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfg, []byte(`{"gate_mode":"off"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_CONFIG", cfg)
	t.Setenv("ARTEX_GATE", "1")

	if got := ResolveGate("", false); got.Mode != GateModeOff || got.Source != GateSourceConfig {
		t.Fatalf("config 应压过 legacy，got %+v", got)
	}
	if got := ResolveGate("enforce", true); got.Mode != GateModeEnforce || got.Source != GateSourceSettings {
		t.Fatalf("settings 应压过 config 与 legacy，got %+v", got)
	}
	t.Setenv("ARTEX_GATE_MODE", "detect")
	if got := ResolveGate("enforce", true); got.Mode != GateModeDetect || got.Source != GateSourceEnv {
		t.Fatalf("env 应压过 settings、config、legacy，got %+v", got)
	}
}

func TestResolveGateLegacyAndDefault(t *testing.T) {
	clearGateEnv(t)

	if got := ResolveGate("", false); got.Mode != GateModeDetect || got.Source != GateSourceDefault {
		t.Fatalf("缺省应为 detect/default，got %+v", got)
	}

	t.Setenv("ARTEX_GATE", "1")
	if got := ResolveGate("", false); got.Mode != GateModeEnforce || got.Source != GateSourceLegacy {
		t.Fatalf("ARTEX_GATE=1 应为 enforce/legacy，got %+v", got)
	}
	t.Setenv("ARTEX_GATE", "0")
	if got := ResolveGate("", false); got.Mode != GateModeOff || got.Source != GateSourceLegacy {
		t.Fatalf("ARTEX_GATE=0 应为 off/legacy，got %+v", got)
	}

	// 空 settings 与空 env 都视为未配置，继续向下。
	t.Setenv("ARTEX_GATE_MODE", "  ")
	if got := ResolveGate("  ", true); got.Mode != GateModeOff || got.Source != GateSourceLegacy {
		t.Fatalf("空白层应跳过并落到 legacy，got %+v", got)
	}
}

func TestResolveGateUnknownFallsBackToDetect(t *testing.T) {
	clearGateEnv(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfg, []byte(`{"gate_mode":"enforce"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_CONFIG", cfg)
	t.Setenv("ARTEX_GATE", "1")

	t.Setenv("ARTEX_GATE_MODE", "1")
	if got := ResolveGate("off", true); got.Mode != GateModeDetect || got.Source != GateSourceEnv {
		t.Fatalf("ARTEX_GATE_MODE 的未知值应停在 env 并回落 detect，不得落到 settings/legacy，got %+v", got)
	}

	t.Setenv("ARTEX_GATE_MODE", "")
	if got := ResolveGate("yes", true); got.Mode != GateModeDetect || got.Source != GateSourceSettings {
		t.Fatalf("settings 未知值应停在 settings，got %+v", got)
	}

	if got := ResolveGate("", false); got.Mode != GateModeEnforce || got.Source != GateSourceConfig {
		t.Fatalf("settings 未设置时应读到 config enforce，got %+v", got)
	}

	if err := os.WriteFile(cfg, []byte(`{"gate_mode":"sometimes"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ResolveGate("", false); got.Mode != GateModeDetect || got.Source != GateSourceConfig {
		t.Fatalf("config 未知值应回落 detect 且来源仍是 config，got %+v", got)
	}

	if err := os.WriteFile(cfg, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_GATE", "true")
	if got := ResolveGate("", false); got.Mode != GateModeDetect || got.Source != GateSourceLegacy {
		t.Fatalf("legacy 的非 0/1 应回落 detect，got %+v", got)
	}

	t.Setenv("ARTEX_GATE_MODE", " ENFORCE ")
	if got := ResolveGate("", false); got.Mode != GateModeEnforce || got.Source != GateSourceEnv {
		t.Fatalf("大小写与空白应被接受，got %+v", got)
	}
}
