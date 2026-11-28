// Package guard implements the safety boundary layer (docs §11): an audit log,
// user-configured intercept-rule evaluation, and Observer/G5 failure attribution.
// Every tool call passes through the PreToolUse hook before executing.
// (The RoE authorization-scope mechanism was removed; a replacement may be added
// later.) Destructive/exfil gating is no longer hard-coded here — it lives in the
// DB intercept rules (seeded as ordinary [内置] rules, so users can disable or
// delete them), evaluated via applyIntercept.
package guard

import (
	"context"
	"encoding/json"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/hook"
)

// AuditEntry records one gated tool call.
type AuditEntry struct {
	TS      int64  `json:"ts"`
	Tool    string `json:"tool"`
	Action  string `json:"action"` // allow|block
	Reason  string `json:"reason,omitempty"`
	Command string `json:"command,omitempty"`
}

// Guard enforces the side-effect policy via agent-core hooks.
type Guard struct {
	mu          sync.Mutex
	audit       []AuditEntry
	attrib      map[string]int // failure attribution counts (Observer / G5)
	reg         *hook.Registry
	interceptor *intercept.Interceptor // optional; nil disables user-configured rules
	egress      *EgressGuard           // optional; 出口敏感指纹拦截,nil 关闭
	tarpit      *tarpitState           // optional; tarpit 熔断,nil 关闭
	roe         RoEConfig              // optional; 零值 / Scope=nil 关闭
	roeWarned   map[roeWarnKey]bool    // warn 模式 (taskID,host) 首次告警去重;随 Guard 生命周期,不持久化
	honeypot    HoneypotConfig         // optional; Check==nil 关闭
}

// roeWarnKey 是 warn-once 去重键:任务 Guard 每任务一个,但 chatGuard 进程级
// 共享,所以 key 必须带 taskID 而不能只按 host。
type roeWarnKey struct {
	taskID int64
	host   string
}

// New creates a Guard without user-configured intercept rules (used for pentest
// tasks where the Interceptor is not yet available).
func New() *Guard { return newGuard(nil) }

// NewWithInterceptor creates a Guard with user-configured intercept rules.
func NewWithInterceptor(ic *intercept.Interceptor) *Guard { return newGuard(ic) }

func newGuard(ic *intercept.Interceptor) *Guard {
	g := &Guard{attrib: map[string]int{}, interceptor: ic}
	g.reg = hook.NewRegistry().
		On(hook.PreToolUse, g.preToolUse).
		On(hook.PostToolUse, g.postToolUse)
	return g
}

// Hooks returns the hook registry to attach to an agent session.
func (g *Guard) Hooks() *hook.Registry { return g.reg }

func (g *Guard) preToolUse(ctx context.Context, ev hook.Event) hook.Result {
	// Extract the shell-command surface for the audit log: Bash + the interactive-shell
	// tools (shell_open's command, shell_send's text). Destructive/exfil gating is no
	// longer hard-coded here — it now lives in the DB intercept rules, evaluated by
	// applyIntercept below. Other tools record an empty command.
	var cmd string
	switch ev.ToolName {
	case "Bash", "shell_open":
		var in struct {
			Command string `json:"command"`
		}
		_ = json.Unmarshal(ev.Input, &in)
		cmd = in.Command
	case "shell_send":
		var in struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(ev.Input, &in)
		cmd = in.Text
	}
	// preToolUse 顺序: egress → RoE → honeypot → tarpit → 现有 intercept。
	// 空 reason 的 allow 只在全部闸门通过后记录,避免 RoE/intercept 拦下时
	// 先留下 allow+block 双行。egress 仍先于任何审计,避免命令原文里的秘密落盘。
	if res, stop := g.checkEgress(ev, cmd); stop {
		return res
	}
	if res, stop := g.checkRoE(ctx, ev, cmd); stop {
		return res
	}
	if res, stop := g.checkHoneypot(ev, cmd); stop {
		return res
	}
	g.checkTarpit(ctx, ev)
	res := g.applyIntercept(ctx, ev)
	if res.Decision == "block" {
		return res
	}
	g.record(ev.ToolName, "allow", "", cmd)
	return res
}

// SetEgress 装配出口审查的敏感指纹集合(server 侧进程内共享一份)。nil = 关闭。
func (g *Guard) SetEgress(e *EgressGuard) {
	g.mu.Lock()
	g.egress = e
	g.mu.Unlock()
}

// checkEgress 是 PreToolUse 第一道:对 Bash 类命令全文与 WebFetch 的 url/body
// 做敏感指纹检查,命中 → deny。审计与文案只记 kind,不回显原文。
// 唯一豁免:命中集合只有 callback_addr,且 roeHosts 抽出的目标非空并全部属于
// 平台自身地址时放行(继续后续闸门,不写拦截)。抽不出 host、混有第三方 host、
// 或同时命中其他 kind 时仍拦截。诊断日志不回显原文。
func (g *Guard) checkEgress(ev hook.Event, cmd string) (hook.Result, bool) {
	g.mu.Lock()
	e := g.egress
	g.mu.Unlock()
	if e == nil {
		return hook.Result{}, false
	}
	var texts []string
	if cmd != "" {
		texts = append(texts, cmd)
	}
	if ev.ToolName == "WebFetch" {
		var in struct {
			URL  string `json:"url"`
			Body string `json:"body"`
		}
		if json.Unmarshal(ev.Input, &in) == nil {
			texts = append(texts, in.URL, in.Body)
		}
	}
	for _, text := range texts {
		if text == "" {
			continue
		}
		kinds := e.CheckKinds(text)
		if len(kinds) == 0 {
			continue
		}
		if len(kinds) == 1 && kinds[0] == "callback_addr" {
			hosts := roeHosts(ev.ToolName, ev.Input, cmd)
			if len(hosts) > 0 && e.OwnsAllHosts(hosts) {
				log.Printf("[guard][egress] 仅命中 callback_addr 且目标均属平台自身地址，%s 放行", ev.ToolName)
				continue
			}
		}
		log.Printf("[guard][egress] 命中平台敏感指纹(%s),%s 外发已拦截", strings.Join(kinds, ","), ev.ToolName)
		return g.block(ev.ToolName, systemBlockMessage("操作包含平台敏感信息，禁止外发"), ""), true
	}
	return hook.Result{}, false
}

// applyIntercept evaluates user-configured intercept rules against the tool call.
// Both rules and the fallback judge receive the complete tool input.
func (g *Guard) applyIntercept(ctx context.Context, ev hook.Event) hook.Result {
	if g.interceptor == nil {
		return hook.Result{}
	}
	if !g.interceptor.IsToolEnabled(ev.ToolName) {
		return hook.Result{}
	}
	ctx = intercept.WithCall(ctx, ev.ToolName, ev.Input)
	dec, matched := g.interceptor.Match(ev.ToolName, ev.Input)
	if !matched {
		// No rule matched. Ask the LLM fallback judge (if enabled); when it is off
		// or unwired, keep current behavior and allow.
		d, judged := g.interceptor.Judge(ctx, ev.ToolName, ev.Input)
		if !judged {
			return hook.Result{}
		}
		dec = d
	}
	switch dec.Action {
	case "deny":
		// 观测:deny 命中不阻塞审批,直接记一条 denied（历史/任务拦截页可见）。
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "denied")
		return g.block(ev.ToolName, systemBlockMessage(dec.Message), "")
	case "allow":
		// Record explicit rule and model approvals so review details remain auditable.
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "allowed")
		return hook.Result{}
	case "ask":
		// If the worker context is already cancelled (task stopped / killed), block
		// immediately without creating a pending record — avoids orphaned DB entries
		// and makes execOne complete fast, reducing the race against drainSynthetic.
		if ctx.Err() != nil {
			return g.block(ev.ToolName, systemBlockMessage("工作已取消，平台安全管控阻止执行"), "")
		}
		convID := intercept.ConvIDFromContext(ctx)
		if !g.interceptor.HandleAsk(ctx, convID, dec, ev.ToolName, ev.Input) {
			return g.block(ev.ToolName, systemBlockMessage("人工审批未通过（用户拒绝或审批超时）"), "")
		}
		return hook.Result{}
	}
	return hook.Result{}
}

// systemBlockMessage frames an intercept block as an ARTEX platform-governance
// decision so the agent does not mistake it for a target-side defense.
//
// The bare reasons ("禁止执行此工具" / "用户拒绝") read exactly like a WAF/403 on
// the target, so a pentest agent's instinct is to bypass them — rewrite the
// command, swap the payload, re-encode, retry. That is both futile (the platform
// blocks the class of action, not one string) and wrong (it's a policy decision,
// not an obstacle to defeat). This prefix states plainly that the block comes
// from the platform, is not the target's protection, and that the operation is
// forbidden — so the agent pivots to another approach instead of evading it.
// Audit/history rows keep the raw reason (see Interceptor.Log); only the
// model-facing tool_result carries this framing.
func systemBlockMessage(reason string) string {
	return "【ARTEX 平台管控·非目标防御】此调用被平台拦截。" +
		"原因：" + reason + "。此操作被禁止。"
}

var reBlocked = regexp.MustCompile(`(?i)\b(403|forbidden|waf|blocked|rate.?limit|429|captcha|denied)\b`)

// postToolUse is the Observer failure-attribution hook (G5): it classifies tool
// results into blocked / error / ok so the planner can change strategy instead
// of giving up at a WAF.
func (g *Guard) postToolUse(_ context.Context, ev hook.Event) hook.Result {
	if ev.ToolName != "Bash" {
		return hook.Result{}
	}
	class := "ok"
	switch {
	case reBlocked.Match(ev.Result):
		class = "blocked"
	case ev.IsError:
		class = "error"
	}
	g.mu.Lock()
	g.attrib[class]++
	g.mu.Unlock()
	return hook.Result{}
}

// Attributions returns failure-attribution counts (Observer / G5).
func (g *Guard) Attributions() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]int, len(g.attrib))
	for k, v := range g.attrib {
		out[k] = v
	}
	return out
}

func (g *Guard) block(tool, reason, cmd string) hook.Result {
	g.record(tool, "block", reason, cmd)
	return hook.Result{Decision: "block", Message: reason}
}

func (g *Guard) record(tool, action, reason, cmd string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.audit = append(g.audit, AuditEntry{TS: time.Now().Unix(), Tool: tool, Action: action, Reason: reason, Command: cmd})
	if len(g.audit) > 2000 {
		g.audit = g.audit[len(g.audit)-2000:]
	}
}

// Audit returns a snapshot of recent gated calls (most recent last).
func (g *Guard) Audit() []AuditEntry {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]AuditEntry, len(g.audit))
	copy(out, g.audit)
	return out
}
