package guard

// 蜜罐方向闸门。误报优先于漏报:默认只对双信号(disposition=block-direction)硬拦。
// 单信号 degrade 告警放行并写 guard 记录;空/未知放行。Check 为 nil 时本闸门不存在。

import (
	"log"
	"strings"

	"github.com/Autumn-27/norma/hook"
)

const (
	honeypotDispositionBlock   = "block-direction"
	honeypotDispositionDegrade = "degrade"
)

// HoneypotConfig 是蜜罐闸门的装配。Check 由 server 注入(guard 不反向依赖 db)。
// Check 返回处置档与中文原因。nil Check = 关闭,preToolUse 行为与未装配时相同。
type HoneypotConfig struct {
	Check func(host string) (disposition string, reason string)
}

// SetHoneypot 装配蜜罐闸门。零值或 Check=nil 等于关闭。
func (g *Guard) SetHoneypot(cfg HoneypotConfig) {
	g.mu.Lock()
	g.honeypot = cfg
	g.mu.Unlock()
}

// checkHoneypot 在 RoE 之后、tarpit 之前看本次调用的目标 host。
// block-direction 硬拦(平台安全策略,不是目标防御);degrade 告警放行。
func (g *Guard) checkHoneypot(ev hook.Event, cmd string) (hook.Result, bool) {
	g.mu.Lock()
	check := g.honeypot.Check
	g.mu.Unlock()
	if check == nil {
		return hook.Result{}, false
	}
	hosts := roeHosts(ev.ToolName, ev.Input, cmd)
	if len(hosts) == 0 {
		return hook.Result{}, false
	}
	for _, host := range hosts {
		disp, reason := check(host)
		switch strings.TrimSpace(disp) {
		case honeypotDispositionBlock:
			if strings.TrimSpace(reason) == "" {
				reason = "确认蜜罐（双信号），停止该方向。这是平台安全策略，不是目标防御，不要绕过。"
			}
			return g.block(ev.ToolName, systemBlockMessage(reason), ""), true
		case honeypotDispositionDegrade:
			if strings.TrimSpace(reason) == "" {
				reason = "蜜罐单信号，降级告警放行（" + host + "）"
			}
			g.record(ev.ToolName, "allow", reason, cmd)
			log.Printf("[guard][honeypot] host %s 单信号降级，告警放行", host)
		default:
			// 空 / none / 未知:放行,不记蜜罐审计。
		}
	}
	return hook.Result{}, false
}
