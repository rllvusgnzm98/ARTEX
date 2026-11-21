// Package dualverify 提供无网络、无凭据的双账号访问控制验证。
package dualverify

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type Expect string

const (
	Allow         Expect = "allow"
	Deny          Expect = "deny"
	MarkerPresent Expect = "marker_present"
	MarkerAbsent  Expect = "marker_absent"
)

type Verdict string

const (
	Verified      Verdict = "verified"
	FalsePositive Verdict = "false_positive"
	ControlsHold  Verdict = "controls_hold"
	Inconclusive  Verdict = "inconclusive"
)

// Request 是可复现模板，不接受真实认证信息。认证位置仅使用 {{AUTH}}。
// 非认证字段同样必须由调用方提供不含秘密的模板。
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

type Footprint struct{ MinTouch, NoDirtyData bool }

// Spec 中 {{RESOURCE_ID}} 和 {{MARKER}} 被替换为私有资源及标记。
// Plant 和 Cleanup 必须显式给出，不能由读请求推断写入或回滚语义。
type Spec struct {
	Target                                Request
	Plant, Cleanup                        Request
	ResourceID, Marker                    string
	Read, Write, SessionToken, TenantRole bool
	AllowWrite                            bool
	Footprint                             Footprint
}

type Step struct {
	ID            string
	Actor         string
	Action        string
	Request       Request
	Expect        Expect
	RequireMarker bool
}

type Plan struct {
	Steps             []Step
	Marker            string
	WriteNotAttempted bool
	Notes             []string
}

// NewMarker 使用 128 位系统随机数生成私有资源标记。
func NewMarker() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "artex-mark-" + hex.EncodeToString(b[:]), nil
}

var actorTokens = map[string]string{
	"public": "", "A": "{{A_AUTH}}", "B": "{{B_AUTH}}",
	"B_expired": "{{B_EXPIRED}}", "B_revoked": "{{B_REVOKED}}",
	"B_wrong_issuer": "{{B_WRONG_ISSUER}}", "B_other_tenant": "{{B_OTHER_TENANT_AUTH}}",
}

func validateRequest(r Request, read bool) error {
	if strings.TrimSpace(r.URL) == "" || strings.TrimSpace(r.Method) == "" {
		return fmt.Errorf("请求 method/url 不能为空")
	}
	m := strings.ToUpper(r.Method)
	if read && m != "GET" && m != "HEAD" {
		return fmt.Errorf("读请求必须使用 GET/HEAD")
	}
	if !read && m != "POST" && m != "PUT" && m != "PATCH" && m != "DELETE" {
		return fmt.Errorf("写请求必须显式使用写方法")
	}
	for k, v := range r.Headers {
		name := strings.ToLower(k)
		if strings.Contains(name, "auth") || strings.Contains(name, "cookie") || strings.Contains(name, "token") || strings.Contains(name, "api-key") || strings.Contains(name, "api_key") {
			if v != "{{AUTH}}" && v != "Bearer {{AUTH}}" {
				return fmt.Errorf("认证头必须仅使用 {{AUTH}} 占位符")
			}
		}
	}
	return nil
}

var markerPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

// BuildPlan 始终生成公开、所有者、跨账号三个读对照。Read 为 false 时
// 这些仍是其他检查族的必要控制；未选择任何检查族则拒绝空计划。
func BuildPlan(s Spec) (Plan, error) {
	if !s.Read && !s.Write && !s.SessionToken && !s.TenantRole {
		return Plan{}, fmt.Errorf("至少选择一个检查族")
	}
	if strings.TrimSpace(s.Marker) == "" || strings.TrimSpace(s.ResourceID) == "" {
		return Plan{}, fmt.Errorf("marker/resource ID 不能为空")
	}
	if !markerPattern.MatchString(s.Marker) {
		return Plan{}, fmt.Errorf("marker 含非法字符，只允许字母数字及 ._~-")
	}
	if err := validateRequest(s.Target, true); err != nil {
		return Plan{}, err
	}
	p := Plan{Marker: s.Marker}
	write := s.Write && (s.AllowWrite || (!s.Footprint.MinTouch && !s.Footprint.NoDirtyData))
	p.WriteNotAttempted = !write
	if !write {
		p.Notes = append(p.Notes, "write not attempted：未启用写入或足迹策略禁止写入")
	}
	add := func(id, actor, action string, r Request, expect Expect, marker bool) {
		replace := strings.NewReplacer("{{RESOURCE_ID}}", s.ResourceID, "{{MARKER}}", s.Marker, "{{AUTH}}", actorTokens[actor])
		out := Request{Method: strings.ToUpper(r.Method), URL: replace.Replace(r.URL), Body: replace.Replace(r.Body), Headers: map[string]string{}}
		for k, v := range r.Headers {
			if actor == "public" && strings.Contains(v, "{{AUTH}}") {
				continue
			}
			out.Headers[k] = replace.Replace(v)
		}
		p.Steps = append(p.Steps, Step{id, actor, action, out, expect, marker})
	}
	if write {
		if err := validateRequest(s.Plant, false); err != nil {
			return Plan{}, fmt.Errorf("plant: %w", err)
		}
		if err := validateRequest(s.Cleanup, false); err != nil {
			return Plan{}, fmt.Errorf("cleanup: %w", err)
		}
		if !strings.Contains(s.Plant.Body+s.Plant.URL, "{{MARKER}}") {
			return Plan{}, fmt.Errorf("plant 必须包含 {{MARKER}}")
		}
		add("plant", "A", "write", s.Plant, Allow, false)
	}
	add("public", "public", "read", s.Target, MarkerAbsent, false)
	add("owner", "A", "read", s.Target, Allow, true)
	add("probe", "B", "read", s.Target, MarkerAbsent, false)
	if s.SessionToken {
		for _, actor := range []string{"B_expired", "B_revoked", "B_wrong_issuer"} {
			add(actor, actor, "read", s.Target, Deny, false)
		}
	}
	if s.TenantRole {
		add("tenant", "B_other_tenant", "read", s.Target, Deny, false)
	}
	if write {
		add("cleanup", "A", "write", s.Cleanup, Allow, false)
	}
	return p, nil
}

type Scope string

const (
	ScopeIn    Scope = "in"
	ScopeOut   Scope = "out"
	ScopeEmpty Scope = "empty-scope"
)

type Observation struct {
	StepID                               string
	Status                               int
	MarkerSeen                           bool
	Scope                                Scope
	OutOfScope, ProxyBypass, NotExecuted bool
}

type StepResult struct {
	StepID        string
	Observation   Observation
	Trusted, Pass bool
	Reason        string
}

type Defect struct {
	Actor   string
	Kind    string
	Verdict Verdict
	Reason  string
}

type Result struct {
	Verdict Verdict
	Reason  string
	Steps   []StepResult
	Defects []Defect
}

func allowed(o Observation) bool { return o.Status >= 200 && o.Status < 300 }
func denied(o Observation) bool  { return o.Status == 401 || o.Status == 403 }

func assess(o Observation, exists bool) (bool, string) {
	if !exists {
		return false, "缺少观察，未执行/未验证"
	}
	if o.NotExecuted {
		return false, "未执行"
	}
	if o.OutOfScope || o.Scope == ScopeOut {
		return false, "out-of-scope：范围外"
	}
	if o.Scope != ScopeIn {
		return false, "empty-scope：缺少明确范围"
	}
	if o.ProxyBypass {
		return false, "proxy-bypass：未经过记录代理"
	}
	if !allowed(o) && !denied(o) {
		return false, "HTTP 状态不明确"
	}
	return true, "已在范围内通过代理记录"
}

// Evaluate 不把缺失观察当成阴性证据；重复或未知步骤是调用错误。
func Evaluate(p Plan, observations []Observation) (Result, error) {
	r := Result{Verdict: Inconclusive}
	steps := map[string]Step{}
	for _, s := range p.Steps {
		if s.ID == "" {
			return Result{}, fmt.Errorf("空 step ID")
		}
		if _, ok := steps[s.ID]; ok {
			return Result{}, fmt.Errorf("重复 step ID")
		}
		steps[s.ID] = s
	}
	for _, id := range []string{"public", "owner", "probe"} {
		if _, ok := steps[id]; !ok {
			return Result{}, fmt.Errorf("缺少必要步骤 %s", id)
		}
	}
	obs := map[string]Observation{}
	for _, o := range observations {
		if _, ok := steps[o.StepID]; !ok {
			return Result{}, fmt.Errorf("未知观察步骤 %s", o.StepID)
		}
		if _, ok := obs[o.StepID]; ok {
			return Result{}, fmt.Errorf("重复观察步骤 %s", o.StepID)
		}
		obs[o.StepID] = o
	}
	byID := map[string]StepResult{}
	for _, s := range p.Steps {
		o, ok := obs[s.ID]
		trusted, reason := assess(o, ok)
		pass := false
		if trusted {
			switch s.Expect {
			case Allow:
				pass = allowed(o)
			case Deny:
				pass = denied(o) && !o.MarkerSeen
			case MarkerPresent:
				pass = allowed(o) && o.MarkerSeen
			case MarkerAbsent:
				pass = !o.MarkerSeen
			}
			if s.RequireMarker {
				pass = pass && o.MarkerSeen
			}
			if pass {
				reason = "符合预期"
			} else {
				reason = "不符合预期"
			}
		}
		sr := StepResult{s.ID, o, trusted, pass, reason}
		r.Steps = append(r.Steps, sr)
		byID[s.ID] = sr
		if s.Actor == "B_expired" || s.Actor == "B_revoked" || s.Actor == "B_wrong_issuer" {
			if trusted && s.Expect == Deny && allowed(o) {
				r.Defects = append(r.Defects, Defect{Actor: s.Actor, Kind: "token-trust", Verdict: Verified, Reason: "应拒绝的令牌被接受"})
			}
		}
		if s.Actor == "B_other_tenant" && trusted && s.Expect == Deny && allowed(o) && o.MarkerSeen {
			r.Defects = append(r.Defects, Defect{Actor: s.Actor, Kind: "cross-tenant", Verdict: Verified, Reason: "跨租户会话读取到 A 的私有标记"})
		}
	}
	pub, a, b := byID["public"], byID["owner"], byID["probe"]
	switch {
	case pub.Trusted && allowed(pub.Observation) && pub.Observation.MarkerSeen:
		r.Verdict, r.Reason = FalsePositive, "公开请求可读取标记：公开数据，不是访问控制漏洞"
		r.Defects = nil
	case !pub.Trusted || !pub.Pass:
		r.Reason = "公开数据排除控制缺失：" + pub.Reason
	case !a.Trusted || !a.Pass:
		r.Reason = "A 正向控制缺失（需允许访问且含标记）：" + a.Reason
	case !b.Trusted:
		r.Reason = "B 探针缺少可信证据：" + b.Reason
	case allowed(b.Observation) && b.Observation.MarkerSeen:
		r.Verdict, r.Reason = Verified, "B 读取到 A 的私有标记"
	case !b.Observation.MarkerSeen:
		r.Verdict, r.Reason = ControlsHold, "A 正向控制成立，B 被拒绝或未读到标记；不是漏洞"
	default:
		r.Reason = "B 状态与标记矛盾，未验证"
	}
	if r.Verdict != FalsePositive {
		kept := r.Defects[:0]
		for _, d := range r.Defects {
			switch d.Kind {
			case "cross-tenant":
				// 跨租户缺陷依赖标记确属 A 的私有数据：需公开排除控制成立且 A 正向控制成立
				if pub.Pass && a.Pass {
					kept = append(kept, d)
				}
			case "token-trust":
				// 令牌信任缺陷只在资源确实非公开（公开被正确拒绝）时才有意义
				if pub.Pass {
					kept = append(kept, d)
				}
			default:
				kept = append(kept, d)
			}
		}
		r.Defects = kept
	}
	return r, nil
}

// Report 只渲染计划中的占位请求及结构化观察，不接收响应正文或凭据。
func Report(r Result, p Plan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# 双账号访问控制验证\n\n结论：%s\n\n%s\n\n标记：%s\n\n## 控制对照矩阵\n\n| 步骤 | 账号 | 动作 | 预期 | 观察 | 通过 |\n|---|---|---|---|---|---|\n", r.Verdict, r.Reason, p.Marker)
	byID := map[string]StepResult{}
	for _, sr := range r.Steps {
		byID[sr.StepID] = sr
	}
	for _, s := range p.Steps {
		sr := byID[s.ID]
		expect := string(s.Expect)
		if s.RequireMarker {
			expect += "+marker_present"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | HTTP %d, marker=%t; %s | %t |\n", s.ID, s.Actor, s.Action, expect, sr.Observation.Status, sr.Observation.MarkerSeen, sr.Reason, sr.Pass)
	}
	b.WriteString("\n## 可复现请求模板（仅认证占位符）\n")
	for _, s := range p.Steps {
		fmt.Fprintf(&b, "\n### %s\n\n```text\n%s %s\n", s.ID, s.Request.Method, s.Request.URL)
		keys := make([]string, 0, len(s.Request.Headers))
		for k := range s.Request.Headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "%s: %s\n", k, s.Request.Headers[k])
		}
		fmt.Fprintf(&b, "\n%s\n```\n", s.Request.Body)
	}
	b.WriteString("\n## 备注\n")
	for _, n := range p.Notes {
		fmt.Fprintf(&b, "- %s\n", n)
	}
	if p.WriteNotAttempted {
		b.WriteString("- 写入：write not attempted；未种植，未执行清理。\n")
	}
	for _, s := range p.Steps {
		sr := byID[s.ID]
		o := sr.Observation
		scope := o.Scope
		if o.OutOfScope {
			scope = ScopeOut
		}
		if scope == "" {
			scope = ScopeEmpty
		}
		fmt.Fprintf(&b, "- %s 范围：%s；proxy-bypass=%t\n", s.ID, scope, o.ProxyBypass)
		if !sr.Trusted {
			fmt.Fprintf(&b, "  - 明确未验证：%s\n", sr.Reason)
		}
		if s.Action == "write" {
			fmt.Fprintf(&b, "  - %s：成功响应=%t；仅响应，持久化/清理结果未独立验证。\n", s.ID, sr.Trusted && sr.Pass)
		}
	}
	for _, t := range r.Defects {
		fmt.Fprintf(&b, "- 访问控制缺陷 %s (%s)：%s（%s）\n", t.Actor, t.Kind, t.Verdict, t.Reason)
	}
	b.WriteString("- 明确未验证：未运行的检查族、读证据之外的写权限、响应以外的副作用。\n")
	return b.String()
}
