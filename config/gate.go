package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 伪装门控取值与来源。来源是 doctor 和 GET /api/gate/stats 展示用的层名。
const (
	GateModeOff     = "off"
	GateModeDetect  = "detect"
	GateModeEnforce = "enforce"

	GateSourceEnv      = "env"
	GateSourceSettings = "settings"
	GateSourceConfig   = "config"
	GateSourceLegacy   = "legacy"
	GateSourceDefault  = "default"

	// GateModeSettingKey 是 settings 表里的键，与 config.json 的 gate_mode 同名不同层。
	GateModeSettingKey = "gate_mode"
)

// GateResolution 是一次模式解析的结果。Mode 只为 off、detect、enforce。
// 未知值会落成 detect，但 Source 仍是提供该值的那一层。
type GateResolution struct {
	Mode   string
	Source string
}

// ResolveGate 按优先级解析伪装门控：
//
//	ARTEX_GATE_MODE > settingsValue（仅 settingsSet）> config.json gate_mode
//	> ARTEX_GATE（1=enforce，0=off）> 默认 detect
//
// 某一层给出非空但无法识别的值时停在该层，模式回落 detect，不再看更低层。
// 空字符串视为该层未配置。大小写不敏感。本函数不访问数据库。
func ResolveGate(settingsValue string, settingsSet bool) GateResolution {
	if v, ok := os.LookupEnv("ARTEX_GATE_MODE"); ok && strings.TrimSpace(v) != "" {
		return resolveLayer(v, GateSourceEnv)
	}
	if settingsSet && strings.TrimSpace(settingsValue) != "" {
		return resolveLayer(settingsValue, GateSourceSettings)
	}
	if v := strings.TrimSpace(Load().GateMode); v != "" {
		return resolveLayer(v, GateSourceConfig)
	}
	if v, ok := os.LookupEnv("ARTEX_GATE"); ok && strings.TrimSpace(v) != "" {
		switch strings.TrimSpace(v) {
		case "1":
			return GateResolution{Mode: GateModeEnforce, Source: GateSourceLegacy}
		case "0":
			return GateResolution{Mode: GateModeOff, Source: GateSourceLegacy}
		default:
			return GateResolution{Mode: GateModeDetect, Source: GateSourceLegacy}
		}
	}
	return GateResolution{Mode: GateModeDetect, Source: GateSourceDefault}
}

func resolveLayer(raw, source string) GateResolution {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case GateModeOff, GateModeDetect, GateModeEnforce:
		return GateResolution{Mode: strings.ToLower(strings.TrimSpace(raw)), Source: source}
	default:
		return GateResolution{Mode: GateModeDetect, Source: source}
	}
}

// GateStatsSnapshot 是运行中进程写到 data/gate/stats.json 的计数快照。
// doctor 只读这个文件；文件不存在表示服务未运行或尚未记录，不能当成零次探测。
type GateStatsSnapshot struct {
	Mode      string    `json:"mode"`
	Source    string    `json:"source"`
	Hits      int64     `json:"hits"`
	Allows    int64     `json:"allows"`
	Bypasses  int64     `json:"bypasses"`
	Decoys    int64     `json:"decoys"`
	UpdatedAt time.Time `json:"updated_at"`
}

// GateStatsPath 是统计快照的路径。dataDir 为空时返回空字符串。
func GateStatsPath(dataDir string) string {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return ""
	}
	return filepath.Join(dataDir, "gate", "stats.json")
}

// ReadGateStats 读取统计快照。文件不存在时返回原样错误，调用方自行说明服务未运行。
func ReadGateStats(dataDir string) (GateStatsSnapshot, error) {
	path := GateStatsPath(dataDir)
	if path == "" {
		return GateStatsSnapshot{}, errors.New("data 目录为空")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return GateStatsSnapshot{}, err
	}
	var snap GateStatsSnapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return GateStatsSnapshot{}, err
	}
	return snap, nil
}
