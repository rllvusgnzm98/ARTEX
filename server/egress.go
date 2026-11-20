package server

// 批 5 B2(设计文档 HONEYPOT-DETECTION-DESIGN.md 二-B「自身防护」第 3 条):出口审查的
// 指纹装配。EgressGuard 是进程级单例(Manager.egress),每个任务的 Guard 在
// taskFromPG / agentGuard 里通过 SetEgress 引用同一份——所以这里只需在「启动」
// 与「LLM profile 变更」(applyLLM 是唯一漏斗)时向这一份注册/替换指纹,所有
// 任务(含已存在的)即时生效,无需逐任务注入。注册只存哈希(见 guard/egress.go),
// 本文件是原文唯一出现的地方:不把原文写入日志或落盘。callback_addr 过短无法
// 注册时只记长度不足,不记原文。

import (
	"encoding/base64"
	"encoding/hex"
	"log"
	"net/url"
	"regexp"
	"strings"

	"github.com/Autumn-27/artex/config"
)

// egressMinSecretLen 与 guard 包未导出的最短指纹长度一致。更短的串不会被
// AddFingerprint 收下。
const egressMinSecretLen = 8

// registerEgressFingerprints 把当前平台敏感信息注册进共享 EgressGuard:
// 激活 LLM profile 的 API key(变更时整体替换)、jwt.key 文件内容(原文/hex/base64
// 三种文本形态)、PG DSN 中的密码、config.json 的 callback_addr。本刀不注册 gate 路径。
// 幂等:重复调用不产生重复指纹(guard.AddFingerprint 内部去重)。
func (s *Server) registerEgressFingerprints() {
	if s.m == nil || s.m.egress == nil {
		return
	}
	eg := s.m.egress
	// 激活 LLM profile 的 API key:profile 可能换了 key,先整类摘掉再注册当前值。
	eg.RemoveKind("llm_api_key")
	if s.m.pg != nil {
		if p, err := s.m.pg.ActiveProfile(); err == nil && p != nil {
			eg.AddFingerprint("llm_api_key", p.APIKey)
		}
	}
	// jwt.key:32 字节签名密钥,出现在命令文本里通常是原文/hex/base64 之一。
	if len(s.jwtKey) > 0 {
		eg.AddFingerprint("jwt_key", string(s.jwtKey))
		eg.AddFingerprint("jwt_key", hex.EncodeToString(s.jwtKey))
		eg.AddFingerprint("jwt_key", base64.StdEncoding.EncodeToString(s.jwtKey))
	}
	// gate 入口路径属伪装门控,本刀不实现、不注册。
	// PG DSN 中的密码(env ARTEX_PG_DSN 或 config.json,与启动解析同一来源)。
	if dsn, _, err := config.PostgresDSN(); err == nil {
		eg.AddFingerprint("pg_password", dsnPassword(dsn))
	}
	// config.json 的 callback_addr(反弹 shell/隧道回连地址)。
	// 过短则指纹不会注册;只记长度,不记原文。随后登记平台自身 host,供回连放行。
	cb := config.CallbackAddr()
	eg.AddFingerprint("callback_addr", cb)
	if cb != "" && len(cb) < egressMinSecretLen {
		log.Printf("[egress] callback_addr 长度 %d 不足 %d，已跳过指纹注册", len(cb), egressMinSecretLen)
	}
	eg.AddOwnInfraHosts(config.OwnInfraHosts()...)
}

// dsnPassword 从 DSN 里取密码:兼容 URL 形态(postgres://user:pass@host/db)
// 与 keyword 形态(host=... password=...)。取不到返回空串(注册方会跳过)。
func dsnPassword(dsn string) string {
	if u, err := url.Parse(dsn); err == nil && u.User != nil {
		if pw, ok := u.User.Password(); ok {
			return pw
		}
	}
	if m := reKeywordPassword.FindStringSubmatch(dsn); m != nil {
		return strings.Trim(m[1], "'")
	}
	return ""
}

// reKeywordPassword 匹配 keyword 形态 DSN 的 password 段(值可单引号包裹)。
var reKeywordPassword = regexp.MustCompile(`(?:^|\s)password=('[^']*'|[^\s]+)`)
