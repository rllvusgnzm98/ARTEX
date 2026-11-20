package config

import (
	"os"
	"strings"
	"time"
)

const (
	// defaultJWTTTL 是访问令牌寿命。168h = 7 天，与历史 jwtTTL 一致。
	defaultJWTTTL = 168 * time.Hour
	// defaultJWTRotation 是签名密钥按龄轮换的周期。0 表示关闭自动轮换。
	defaultJWTRotation = 720 * time.Hour
	// defaultJWTGrace 是轮换后加在 TTL 之外的宽限。retire_at 另有 7 天下限。
	defaultJWTGrace = 24 * time.Hour
)

// JWTTTL 解析 ARTEX_JWT_TTL。环境变量优先于配置文件 jwt_ttl；空值、0 或
// 解析失败回落 168h。
func JWTTTL() time.Duration {
	return durationSetting("ARTEX_JWT_TTL", Load().JWTTTL, defaultJWTTTL, false)
}

// JWTRotationPeriod 解析 ARTEX_JWT_ROTATION_PERIOD。0 关闭按龄轮换；解析失败
// 回落 720h。
func JWTRotationPeriod() time.Duration {
	return durationSetting("ARTEX_JWT_ROTATION_PERIOD", Load().JWTRotationPeriod, defaultJWTRotation, true)
}

// JWTGrace 解析 ARTEX_JWT_GRACE。这是 TTL 之外的额外宽限，0 合法；解析失败回落 24h。
func JWTGrace() time.Duration {
	return durationSetting("ARTEX_JWT_GRACE", Load().JWTGrace, defaultJWTGrace, true)
}

// durationSetting 读环境变量，未设置时再读配置文件里的原始字符串。
// 环境变量已设置但解析失败时直接回落 fallback，不再看文件。
func durationSetting(envKey, fileValue string, fallback time.Duration, allowZero bool) time.Duration {
	if raw, ok := os.LookupEnv(envKey); ok {
		if d, ok := parseDurationSetting(raw, allowZero); ok {
			return d
		}
		return fallback
	}
	if d, ok := parseDurationSetting(fileValue, allowZero); ok {
		return d
	}
	return fallback
}

func parseDurationSetting(raw string, allowZero bool) (time.Duration, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 || (d == 0 && !allowZero) {
		return 0, false
	}
	return d, true
}
