package agent

import (
	"bytes"
	"sync"
	"sync/atomic"
	"text/template"
	"time"
)

// PromptOverride, if set, returns the stored system-prompt template for an agent
// key and whether one exists. The server wires it to the PG agent_prompts table.
// When nil or no override exists, agents use their built-in default prompt — so
// behavior is identical until a user edits a prompt in the UI.
var PromptOverride func(agentKey string) (string, bool)

// Prompt-variable structs — fields mirror each agent's catalog (docs §5a) so a
// user template referencing a catalog variable renders; referencing anything else
// fails template execution and falls back to the built-in default.
type PlannerVars struct{ Goal, Scope, AssetSummary, DataDir, Now string }
type WorkerVars struct {
	ProxyAddr, WorkerName, DataDir, Now string
	// Intranet 为 true 时,workerSystem 在正文之后追加 worker.intranet 短纪律变体
	// (只追加,不替换 worker 正文,也不覆盖进场预塞)。
	Intranet bool
}
type MainVars struct{ Goal, AssetSummary, FindingsSummary, DataDir, Now string }
type GoalsVars struct{ EngagementDescription, DataDir, Now string }

// nowStr is the server-local wall-clock string exposed as the universal {{.Now}}
// prompt variable. renderSystem runs on every agent turn/round, so this is fresh
// each run — a prompt can subtract it from a fixed start stamp to reason about
// elapsed time (e.g. a timed benchmark's "last N hours" window).
func nowStr() string { return time.Now().Format("2006-01-02 15:04:05 MST") }

// renderSystem returns the rendered system-prompt BODY (段 [A]) for agentKey.
// Precedence: the DB-stored template (if any) over the built-in default template
// (def). BOTH are Go templates now — the built-in default is seeded into the DB
// verbatim, so the two paths render identically until a user edits the prompt.
// Rendering always runs (def used to be pre-substituted plain text; it is now a
// {{.Var}} template like the DB one). On any render error we fall back to the
// default template, then to the raw default string — an agent never starts with a
// half-rendered prompt. Callers append the code-owned tail (trafficTool / 中间产物
// 输出规约) AFTER this, so those can't be edited away via the DB body.
func renderSystem(agentKey, def string, vars any) string {
	tmpl := def
	if PromptOverride != nil {
		if t, ok := PromptOverride(agentKey); ok && t != "" {
			tmpl = t
		}
	}
	if out, err := renderTmpl(tmpl, vars); err == nil {
		return out
	}
	// DB template broke (e.g. references an out-of-catalog var) → code default.
	if out, err := renderTmpl(def, vars); err == nil {
		return out
	}
	return def
}

// renderSystemVariant 同 renderSystem,但支持变体 key(如 worker 的 "intranet"):
// 先试 agentKey+"."+variant 的 DB 覆盖,没有再退回内置变体默认(def)。
// 变体模板渲染失败同样退回 def,绝不出半渲染提示词。本仓把变体只用于追加段,
// 不替换 worker 主正文,也不覆盖进场预塞。
func renderSystemVariant(agentKey, variant, def string, vars any) string {
	if variant != "" && PromptOverride != nil {
		if tmpl, ok := PromptOverride(agentKey + "." + variant); ok && tmpl != "" {
			if out, err := renderTmpl(tmpl, vars); err == nil {
				return out
			}
		}
	}
	if out, err := renderTmpl(def, vars); err == nil {
		return out
	}
	return def
}

// Parsed templates keyed by their source text. Built-in prompts never change and
// DB overrides only change on edit, so each text is parsed once. Size is capped
// so repeated prompt edits can't grow it without bound.
var (
	tmplCache  sync.Map // string → *template.Template
	tmplCached atomic.Int64
)

const tmplCacheMax = 256

func compileTmpl(tmpl string) (*template.Template, error) {
	if t, ok := tmplCache.Load(tmpl); ok {
		return t.(*template.Template), nil
	}
	t, err := template.New("p").Option("missingkey=error").Parse(tmpl)
	if err != nil {
		return nil, err
	}
	if tmplCached.Load() >= tmplCacheMax {
		tmplCache.Range(func(k, _ any) bool { tmplCache.Delete(k); return true })
		tmplCached.Store(0)
	}
	if _, loaded := tmplCache.LoadOrStore(tmpl, t); !loaded {
		tmplCached.Add(1)
	}
	return t, nil
}

func renderTmpl(tmpl string, vars any) (string, error) {
	t, err := compileTmpl(tmpl)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, vars); err != nil {
		return "", err
	}
	return b.String(), nil
}
