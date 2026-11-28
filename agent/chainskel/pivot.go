package chainskel

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/norma/skill"
)

// pivotMarker 是骨架行里"转向"条目的字段标记(9 类骨架统一为
// "- 场景:...|判据:...|转向:..." 的蒸馏格式)。
const pivotMarker = "转向:"

// PivotHints 从类别骨架中抽出"转向"类条目,拼成停滞干预消息里的类别化转向
// 建议段:tags 优先(规整+合法性过滤,至多 MaxTagsPerIntent 个),空时回退
// summary 关键词匹配(Match);每个命中类别取前 max 条"转向:"后的内容。
// 无匹配类别、骨架缺失、或骨架里抽不到转向条目时返回 ""(调用方用通用措辞)。
func PivotHints(tags []string, summary string, max int) string {
	if max <= 0 {
		return ""
	}
	var cats []string
	for _, t := range NormalizeChainTags(tags) {
		if Valid(t) {
			cats = append(cats, t)
		}
		if len(cats) >= MaxTagsPerIntent {
			break
		}
	}
	if len(cats) == 0 {
		cats = Match(summary)
	}
	if len(cats) == 0 {
		return ""
	}
	var lines []string
	for _, c := range cats {
		sk, ok := Skeleton(c)
		if !ok {
			continue // 骨架缺失:静默跳过
		}
		n := 0
		for _, line := range strings.Split(sk, "\n") {
			idx := strings.Index(line, pivotMarker)
			if idx < 0 {
				continue
			}
			hint := strings.TrimSpace(line[idx+len(pivotMarker):])
			if hint == "" {
				continue
			}
			lines = append(lines, "["+c+"] "+hint)
			n++
			if n >= max {
				break
			}
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return "同类场景的可选转向路径(摘自反问决策链骨架,按本意图攻击面选取,逐条评估是否适用):\n- " +
		strings.Join(lines, "\n- ")
}

// PivotHintsForIntent 是 PivotHints 的意图 payload 入口(server/engine 接线用):
// 从 payload 解出 chain_tags/summary 后走同一逻辑;payload 解析失败返回 ""。
func PivotHintsForIntent(payload json.RawMessage, max int) string {
	var p struct {
		Summary   string   `json:"summary"`
		ChainTags []string `json:"chain_tags"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return ""
	}
	return PivotHints(p.ChainTags, p.Summary, max)
}

var categorySkillHints = map[string]string{
	"web":      "target-health-triage / oss-cms-patch-audit / async-client-oob-chain / blind-oracle-extractor / web-rce-gadget-playbook / weblogic-java-rce / js-api-recon / tbhm-app-analysis / playwright-cli（带外回连用 oob_allocate/oob_poll）",
	"audit":    "oss-cms-patch-audit / web-rce-gadget-playbook / js-api-recon",
	"patch":    "oss-cms-patch-audit",
	"identity": "async-client-oob-chain / web-rce-gadget-playbook / playwright-cli",
	"recon":    "tbhm-recon / js-api-recon / target-health-triage",
	"ad":       "windows-ad-postex / ad-exchange-relay / cross-os-payload-encoding",
	"pivot":    "multi-hop-pivoting / cross-os-payload-encoding",
	"priv":     "web-rce-gadget-playbook / windows-ad-postex / cross-os-payload-encoding",
}

const internalReconSkillHint = "windows-ad-postex / multi-hop-pivoting / cross-os-payload-encoding"

// isInternalHostRecon detects LAN / single-IP / Windows / AD host-recon intents
// where external enterprise domain/ASN/SPA recon skills (tbhm-recon, js-api-recon)
// would be irrelevant noise.
func isInternalHostRecon(summary string) bool {
	lower := strings.ToLower(summary)
	for _, ext := range []string{"子域", "subdomain", "dmarc", "asn", "webpack", "vite", "spa", "前端", "js 路由", "企业资产"} {
		if strings.Contains(lower, ext) {
			return false
		}
	}
	for _, lan := range []string{"192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31."} {
		if strings.Contains(lower, lan) {
			return true
		}
	}
	for _, hostKw := range []string{"全端口", "smb", "winrm", "rdp", "netbios", "内网", "跳板", "域控", "域成员", "windows server"} {
		if strings.Contains(lower, hostKw) {
			return true
		}
	}
	return false
}

// prioritySkillsForSummary returns high-confidence skill names directly anchored
// by concrete tech/protocol/scenario keywords in the intent summary.
func prioritySkillsForSummary(summary string) []string {
	lower := strings.ToLower(summary)
	var out []string
	seen := map[string]bool{}
	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	hasAny := func(kws ...string) bool {
		for _, kw := range kws {
			if strings.Contains(lower, kw) {
				return true
			}
		}
		return false
	}
	if hasAny("weblogic", "wls-wsat", "xmldecoder", "cve-2017-10271", ":7001", "iiop", "serializedsystemini") {
		add("weblogic-java-rce")
	}
	if hasAny("portproxy", "socks", "chisel", "rcsocks", "跳板", "多跳", "隧道", "内网横向", "双网卡") {
		add("multi-hop-pivoting")
	}
	if hasAny("zerologon", "dcsync", "kerberos", "printnightmare", "spoolss", "ms17-010", "eternalblue", "wmiexec", "secretsdump", "域控", "域渗透", "域成员") {
		add("windows-ad-postex")
	}
	if hasAny("exchange", "owa", "petitpotam", "coercer", "ntlm relay", "efsrpc", "强制认证") {
		add("ad-exchange-relay")
	}
	if hasAny("powershell", "gbk", "utf-16", "magic_quotes", "escapeshellcmd", "cmd /c", "base64") {
		add("cross-os-payload-encoding")
	}
	return out
}

// skillDescriptionTrunc 是注入提示里单条技能描述的长度上限（字符）：
// 描述只为路由决策服务，保持紧凑（80 字符内）防止首条消息膨胀。
const skillDescriptionTrunc = 80

// SkillCatalogResolver 由 server 层在启动时注入：复用 skillDirCache 并按 DB 的
// agent_visibility 过滤出对指定 agentKey 可见的技能集合及其描述，避免每次派单扫盘，
// 也避免向 worker 推荐已在 UI 关闭/解绑的技能。nil 时退化为只读本地缓存扫描。
var SkillCatalogResolver func(agentKey string) (allowed map[string]bool, descs map[string]string)

var fallbackSkillCache struct {
	mu    sync.Mutex
	dir   string
	sig   string
	descs map[string]string
}

func resolveReadOnlySkillDir() string {
	if v := strings.TrimSpace(os.Getenv("ARTEX_SKILL_DIR")); v != "" {
		return v
	}
	if v := strings.TrimSpace(config.Load().SkillDir); v != "" {
		return v
	}
	return filepath.Join(config.BaseDir(), "skills")
}

func formatSkillDescription(raw string) string {
	desc := strings.Join(strings.Fields(raw), " ")
	if desc == "" {
		return ""
	}
	runes := []rune(desc)
	if len(runes) > skillDescriptionTrunc {
		return string(runes[:skillDescriptionTrunc]) + "…"
	}
	return desc
}

func skillDirSig(dir string) (string, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", false
	}
	var b strings.Builder
	for _, e := range entries {
		var p string
		switch {
		case e.IsDir():
			p = filepath.Join(dir, e.Name(), "SKILL.md")
		case strings.HasSuffix(e.Name(), ".md"):
			p = filepath.Join(dir, e.Name())
		default:
			continue
		}
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		fmt.Fprintf(&b, "%s|%d|%d\n", p, fi.Size(), fi.ModTime().UnixNano())
	}
	return b.String(), true
}

// resolveWorkerSkillCatalog 返回对 worker 可见的技能集合（nil 表示不做可见性剔除）
// 以及 name → 截断单行描述。
func resolveWorkerSkillCatalog() (map[string]bool, map[string]string) {
	if SkillCatalogResolver != nil {
		allowed, rawDescs := SkillCatalogResolver("worker")
		descs := make(map[string]string, len(rawDescs))
		for k, v := range rawDescs {
			if d := formatSkillDescription(v); d != "" {
				descs[k] = d
			}
		}
		return allowed, descs
	}
	dir := resolveReadOnlySkillDir()
	sig, ok := skillDirSig(dir)
	if !ok {
		return nil, nil
	}
	fallbackSkillCache.mu.Lock()
	defer fallbackSkillCache.mu.Unlock()
	if fallbackSkillCache.dir == dir && fallbackSkillCache.sig == sig {
		return nil, fallbackSkillCache.descs
	}
	reg, err := skill.LoadDir(dir)
	if err != nil {
		return nil, nil
	}
	out := make(map[string]string)
	for _, sk := range reg.List() {
		if d := formatSkillDescription(sk.Description); d != "" {
			out[sk.Name] = d
		}
	}
	fallbackSkillCache.dir, fallbackSkillCache.sig, fallbackSkillCache.descs = dir, sig, out
	return nil, out
}

// withSkillDescriptions 把 "a / b / c（备注）" 形式的技能清单行按可见性过滤并改写成
// "a — 描述； b — 描述； c — 描述（备注）"。allowed 非 nil 时仅保留对 worker 可见的技能；
// 查不到描述的可见技能降级为裸名；全部被禁用时返回空串（若有尾注则仅保留尾注）。
func withSkillDescriptions(hint string, allowed map[string]bool, descs map[string]string) string {
	names := strings.Split(hint, " / ")
	if len(names) == 0 {
		return hint
	}
	var out []string
	var pendingSuffix string
	hasDesc := false
	for _, raw := range names {
		name, suffix := strings.TrimSpace(raw), ""
		if i := strings.Index(raw, "（"); i >= 0 {
			name, suffix = strings.TrimSpace(raw[:i]), raw[i:]
		}
		if allowed != nil && !allowed[name] {
			if suffix != "" {
				pendingSuffix += suffix
			}
			continue
		}
		if d, ok := descs[name]; ok {
			hasDesc = true
			out = append(out, name+" — "+d+suffix)
		} else {
			out = append(out, name+suffix)
		}
	}
	if len(out) == 0 {
		return strings.TrimSpace(pendingSuffix)
	}
	if pendingSuffix != "" {
		out[len(out)-1] += pendingSuffix
	}
	if hasDesc {
		return strings.Join(out, "； ")
	}
	return strings.Join(out, " / ")
}

func RefsGuideForIntent(_ json.RawMessage) string { return "" }

// SkillGuideForIntent emits a concise skill & managed-OOB routing hint keyed off
// the intent's chain_tags (or summary fallback) plus high-confidence keyword matches.
// Returns "" when neither category nor keyword matches.
func SkillGuideForIntent(payload json.RawMessage) string {
	var p struct {
		Summary   string   `json:"summary"`
		ChainTags []string `json:"chain_tags"`
	}
	if len(payload) == 0 || json.Unmarshal(payload, &p) != nil {
		return ""
	}
	var cats []string
	for _, t := range NormalizeChainTags(p.ChainTags) {
		if Valid(t) {
			cats = append(cats, t)
		}
		if len(cats) >= MaxTagsPerIntent {
			break
		}
	}
	if len(cats) == 0 {
		cats = Match(p.Summary)
	}
	priority := prioritySkillsForSummary(p.Summary)
	if len(cats) == 0 && len(priority) == 0 {
		return ""
	}
	allowed, descs := resolveWorkerSkillCatalog()
	var lines []string
	if len(priority) > 0 {
		if rendered := withSkillDescriptions(strings.Join(priority, " / "), allowed, descs); rendered != "" {
			lines = append(lines, "[高匹配] 动手前先调 Skill 加载: "+rendered)
		}
	}
	for _, cat := range cats {
		hint, ok := categorySkillHints[cat]
		if !ok || hint == "" {
			continue
		}
		if cat == "recon" && isInternalHostRecon(p.Summary) {
			hint = internalReconSkillHint
		}
		if rendered := withSkillDescriptions(hint, allowed, descs); rendered != "" {
			lines = append(lines, "["+cat+"] 优先按需调 Skill 加载: "+rendered)
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return "\n\n【可用专项技能与受管工具提示（遇到对应场景先调 Skill 加载再手写脚本）】:\n- " + strings.Join(lines, "\n- ")
}
