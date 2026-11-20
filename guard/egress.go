package guard

// 批 5 B2(设计文档 HONEYPOT-DETECTION-DESIGN.md 二-B「自身防护」第 3 条):出口审查。
// 反 AI 蜜罐的收割目标是平台敏感信息(LLM API key、jwt.key、gate 入口路径、
// PG DSN 密码、callback_addr)。本文件在 guard 内置一道敏感指纹拦截:注册时只存
// 原文的 SHA256 前缀(16 个十六进制字符 = 8 字节),不存原文;检查时按注册过的
// 原文长度在待检文本上滑窗取哈希,与指纹集常量时间比对。命中即 deny。
//
// 成本说明:滑窗哈希是 O(文本长 × 原文长) × 不同长度个数。检查面只有 Bash 类
// 命令全文与 WebFetch 的 url/body,正常都在 KB 级,代价可忽略。

import (
	"crypto/sha256"
	"crypto/subtle"
	"net"
	"sort"
	"strings"
	"sync"
)

// egressMinSecretLen 是注册指纹的最短原文长度:更短的串(如弱密码)在普通命令里
// 出现率太高,滑窗必然误报,直接拒绝注册。
const egressMinSecretLen = 8

// egressFingerprint 是一条敏感指纹:只存哈希前缀与原文长度,绝不存原文。
type egressFingerprint struct {
	kind   string
	sum    [sha256.Size]byte
	length int // 原文长度,滑窗窗口大小
}

// EgressGuard 是敏感指纹集合,进程内共享(server 装配时注册,所有任务的 guard
// 引用同一份,profile 变更重新注册即对全部任务生效)。并发安全。
type EgressGuard struct {
	mu  sync.RWMutex
	fps []egressFingerprint
	// byLen 是按原文长度分组的指纹索引,Check 时只需对文本里每个长度各滑一次窗。
	byLen map[int][]int // length → fps 下标
	// own 是平台自身 host（已归一）。与 fps 共用 mu。
	own map[string]struct{}
}

func NewEgressGuard() *EgressGuard {
	return &EgressGuard{byLen: map[int][]int{}, own: map[string]struct{}{}}
}

// AddFingerprint 注册一条敏感指纹(内部做哈希,不存原文)。空串/过短串静默跳过;
// 同一 (kind, 原文) 重复注册是幂等 no-op。
func (e *EgressGuard) AddFingerprint(kind, secret string) {
	if len(secret) < egressMinSecretLen {
		return
	}
	sum := sha256.Sum256([]byte(secret))
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, fp := range e.fps {
		if fp.kind == kind && fp.length == len(secret) && fp.sum == sum {
			return // 幂等:重复注册不产生重复项
		}
	}
	e.fps = append(e.fps, egressFingerprint{kind: kind, sum: sum, length: len(secret)})
	e.byLen[len(secret)] = append(e.byLen[len(secret)], len(e.fps)-1)
}

// RemoveKind 摘掉某类的全部指纹(LLM profile 变更时整体替换 llm_api_key 用)。
func (e *EgressGuard) RemoveKind(kind string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	kept := e.fps[:0]
	for _, fp := range e.fps {
		if fp.kind != kind {
			kept = append(kept, fp)
		}
	}
	e.fps = kept
	e.byLen = map[int][]int{}
	for i, fp := range e.fps {
		e.byLen[fp.length] = append(e.byLen[fp.length], i)
	}
}

// Check 在 text 里做滑窗哈希比对;命中返回该指纹的 kind。与每个候选指纹的比较
// 走 subtle.ConstantTimeCompare,不随命中位置提前退出比较本身。
func (e *EgressGuard) Check(text string) (kind string, hit bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.fps) == 0 || len(text) < egressMinSecretLen {
		return "", false
	}
	for length, idxs := range e.byLen {
		if length > len(text) {
			continue
		}
		for i := 0; i+length <= len(text); i++ {
			sum := sha256.Sum256([]byte(text[i : i+length]))
			for _, idx := range idxs {
				if subtle.ConstantTimeCompare(sum[:], e.fps[idx].sum[:]) == 1 {
					return e.fps[idx].kind, true
				}
			}
		}
	}
	return "", false
}

// CheckKinds 返回 text 命中的全部 kind。去重后按字典序排列，多次调用顺序稳定。
// 无命中返回 nil。比对方式与 Check 相同，不改变 Check 的返回语义。
func (e *EgressGuard) CheckKinds(text string) []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.fps) == 0 || len(text) < egressMinSecretLen {
		return nil
	}
	seen := make(map[string]struct{})
	var kinds []string
	for length, idxs := range e.byLen {
		if length > len(text) {
			continue
		}
		for i := 0; i+length <= len(text); i++ {
			sum := sha256.Sum256([]byte(text[i : i+length]))
			for _, idx := range idxs {
				if subtle.ConstantTimeCompare(sum[:], e.fps[idx].sum[:]) == 1 {
					k := e.fps[idx].kind
					if _, ok := seen[k]; ok {
						continue
					}
					seen[k] = struct{}{}
					kinds = append(kinds, k)
				}
			}
		}
	}
	sort.Strings(kinds)
	return kinds
}

// AddOwnInfraHosts 登记平台自身 host。大小写不敏感，去端口、去 IPv6 方括号、
// 去尾部点；空串跳过。与指纹集共用同一把锁。
func (e *EgressGuard) AddOwnInfraHosts(hosts ...string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.own == nil {
		e.own = map[string]struct{}{}
	}
	for _, h := range hosts {
		key := normalizeOwnHost(h)
		if key == "" {
			continue
		}
		e.own[key] = struct{}{}
	}
}

// IsOwnInfraHost 报告 host 是否已登记为平台自身地址（先按 AddOwnInfraHosts 的规则归一）。
func (e *EgressGuard) IsOwnInfraHost(host string) bool {
	key := normalizeOwnHost(host)
	if key == "" {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, ok := e.own[key]
	return ok
}

// OwnsAllHosts 仅当 hosts 非空且每一个都是平台自身 host 时为 true。
func (e *EgressGuard) OwnsAllHosts(hosts []string) bool {
	if len(hosts) == 0 {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, h := range hosts {
		key := normalizeOwnHost(h)
		if key == "" {
			return false
		}
		if _, ok := e.own[key]; !ok {
			return false
		}
	}
	return true
}

// normalizeOwnHost 归一自身 host：去空白、去端口、去 IPv6 方括号、去尾部点、转小写。
// 空结果表示应跳过。
func normalizeOwnHost(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	if strings.HasPrefix(h, "[") {
		if i := strings.IndexByte(h, ']'); i >= 0 {
			h = h[1:i]
		}
	}
	h = strings.TrimSpace(h)
	h = strings.TrimRight(h, ".")
	return strings.ToLower(h)
}
