package guard

import (
	"net"
	"strings"
)

// ScopeRule is one RoE authorization-scope rule. Kind is one of
// domain|exact_domain|ip|cidr|icp|keyword (or exclude_* aliases with Exclude).
// When Exclude is true, any matching host is marked ScopeOut regardless of
// inclusion rules or AllowLocal.
type ScopeRule struct {
	Kind    string
	Value   string
	Exclude bool
}

// ScopeVerdict is the three-state result of a scope check.
type ScopeVerdict int

const (
	// ScopeUnknown means the task has no registered scope — 未登记范围,放行(保持现状语义)。
	ScopeUnknown ScopeVerdict = iota
	// ScopeIn means the host matches at least one scope rule.
	ScopeIn
	// ScopeOut means scope rules exist but none match the host (or an exclusion rule matched).
	ScopeOut
)

func (v ScopeVerdict) String() string {
	switch v {
	case ScopeIn:
		return "in"
	case ScopeOut:
		return "out"
	default:
		return "unknown"
	}
}

type scopeBucket struct {
	domains      []string
	exactDomains []string
	ips          []net.IP
	cidrs        []*net.IPNet
}

func (b *scopeBucket) add(kind, val string) bool {
	switch kind {
	case "domain", "icp":
		// icp 按 domain 语义处理(域名后缀匹配)。
		d := normalizeHost(val)
		if d != "" && net.ParseIP(d) == nil {
			b.domains = append(b.domains, d)
			return true
		}
	case "exact_domain":
		d := normalizeHost(val)
		if d != "" && net.ParseIP(d) == nil {
			b.exactDomains = append(b.exactDomains, d)
			return true
		}
	case "ip":
		if ip := net.ParseIP(normalizeHost(val)); ip != nil {
			b.ips = append(b.ips, ip)
			return true
		}
	case "cidr":
		if _, n, err := net.ParseCIDR(val); err == nil {
			b.cidrs = append(b.cidrs, n)
			return true
		}
	}
	return false
}

func (b *scopeBucket) match(h string) bool {
	if ip := net.ParseIP(h); ip != nil {
		for _, rip := range b.ips {
			if rip.Equal(ip) {
				return true
			}
		}
		for _, n := range b.cidrs {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	for _, d := range b.exactDomains {
		if h == d {
			return true
		}
	}
	for _, d := range b.domains {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

func normalizeScopeRuleKind(kind string, exclude bool) (canon string, isExclude bool) {
	k := strings.ToLower(strings.TrimSpace(kind))
	switch k {
	case "exclude_domain", "exclude_root_domain":
		return "domain", true
	case "exclude_exact_domain", "exclude_subdomain":
		return "exact_domain", true
	case "exclude_ip":
		return "ip", true
	case "exclude_cidr":
		return "cidr", true
	case "subdomain":
		return "exact_domain", exclude
	case "root_domain":
		return "domain", exclude
	default:
		return k, exclude
	}
}

// ScopeMatcher matches hosts against a task's RoE scope rules. Pure and
// stateless; safe for concurrent use.
type ScopeMatcher struct {
	include       scopeBucket
	exclude       scopeBucket
	hasInclusions bool
	hasRules      bool
	// AllowLocal treats worker-local targets (loopback / link-local / localhost)
	// as in-scope: 本机操作不算出界。默认开;关掉后本机地址也走范围匹配。
	// 注意:RFC1918 内网地址不在放行之列——内网任务必须把目标网段登记进
	// task_scope,否则 RoE 对内网形同虚设。
	AllowLocal bool
}

// NewScopeMatcher compiles rules into a matcher. Rules with unparsable values
// are skipped. An empty (or all-skipped) rule set yields ScopeUnknown verdicts.
func NewScopeMatcher(rules []ScopeRule) *ScopeMatcher {
	m := &ScopeMatcher{AllowLocal: true}
	for _, r := range rules {
		v := strings.TrimSpace(r.Value)
		if v == "" {
			continue
		}
		kind, isExclude := normalizeScopeRuleKind(r.Kind, r.Exclude)
		if kind == "keyword" {
			// 死规则:不参与匹配(见 db/task_scope.go covTargetCTE 注释)。
			continue
		}
		if isExclude {
			if m.exclude.add(kind, v) {
				m.hasRules = true
			}
			continue
		}
		if m.include.add(kind, v) {
			m.hasRules = true
			m.hasInclusions = true
		}
	}
	return m
}

// Check reports whether host is in scope. host may carry a :port (stripped)
// and is matched case-insensitively with trailing dots removed. Exclusions take
// precedence over both wildcard inclusions and AllowLocal.
func (m *ScopeMatcher) Check(host string) ScopeVerdict {
	if !m.hasRules {
		return ScopeUnknown
	}
	h := normalizeHost(host)
	if h == "" {
		return ScopeUnknown
	}
	if m.exclude.match(h) {
		return ScopeOut
	}
	if m.AllowLocal && isLocalHost(h) {
		return ScopeIn
	}
	if !m.hasInclusions {
		return ScopeUnknown
	}
	if m.include.match(h) {
		return ScopeIn
	}
	return ScopeOut
}

// InScope is the boolean convenience form of Check (true only for ScopeIn).
func (m *ScopeMatcher) InScope(host string) bool { return m.Check(host) == ScopeIn }

// normalizeHost lowercases, trims a trailing dot and an optional :port, and
// strips IPv6 brackets.
func normalizeHost(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	if strings.HasPrefix(h, "[") {
		if i := strings.Index(h, "]"); i >= 0 {
			return strings.ToLower(strings.TrimSuffix(h[1:i], "."))
		}
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// isLocalHost reports whether h is a worker-local target: loopback, link-local,
// unspecified addresses, and the "localhost" name.
func isLocalHost(h string) bool {
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
	}
	return false
}
