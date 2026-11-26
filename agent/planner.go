package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/Autumn-27/artex/agent/chainskel"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

// Planner is the event-driven LLM planner (docs §4.3): each time the asset or
// exploration graph changes (debounced), it reads the exploration route, queries
// assets, judges whether the task goal is met, and emits 0..N exploration intents
// into the frontier. It is the sole intent generator.
type Planner struct {
	findingRecorder   FindingRecorder
	prov              llm.Provider
	model             string
	tx                *transcript.Store                      // raw LLM conversation persistence (nil = off)
	window            int                                    // context window in tokens (for compaction)
	windowFn          func() int                             // optional dynamic task-chain minimum
	maxTurns          int                                    // max agent turns per run (0 = unlimited)
	killWork          func(context.Context, int64) error     // engine callback to terminate a running work (nil = off)
	steerWork         func(intentID int64, msg string) error // engine callback to steer a running work mid-run (nil = off)
	proxyAddr         string                                 // recording proxy for WebFetch (empty = direct)
	proxyCACert       string                                 // recording proxy's CA cert path (HTTPS verify)
	webSearch         WebSearchOpts                          // web_search tool backend selection (off by default)
	workDir           string                                 // shared work dir (surfaced in prompt as artifact-output target)
	injectConstraints func() bool                            // resolver: inject task operation constraints into system prompt? (nil = yes)
	nonStreamingFn    func() bool                            // resolver: use non-streaming (Complete) path? (nil = streaming)
	noaEnabledFn      func() bool                            // resolver: use experimental noa compaction? (nil = off)
	maxTokensFn       func() int                             // resolver: per-reply output cap (nil/0 = send no cap)
	compactor         *Compactor                             // cold-node compaction (§7); nil = disabled
	uaFn              func(taskID int64) string              // 按任务稳定 UA → WebFetch 请求头；nil = 官方默认
	guardFn           func(taskID int64) harness.HookRunner  // 任务级 Guard hooks（用于规划者开局探测经由范围/拦截规则检查）

	// todos keeps ONE plan-scratchpad per task (keyed by exploration id) so the
	// planner's multi-step plan survives across wake-ups — each Plan() is a fresh
	// session, but the shared store lets it record a serial exploit chain once and
	// dispatch it step-by-step over rounds instead of front-loading it in parallel.
	todoMu sync.Mutex
	todos  map[int64]*actool.TodoStore

	// probes keeps ONE opening-probe allowance per task (keyed by exploration id).
	// The planner is woken on every graph change, so a per-round counter would
	// reset the "at most PlannerProbeLimit probes at the opening" boundary on each
	// wake-up and bound nothing; keeping it here makes the cap hold across rounds.
	probeMu sync.Mutex
	probes  map[int64]*plannerProbeState
}

func NewPlanner(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *Planner {
	return &Planner{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, todos: map[int64]*actool.TodoStore{}, probes: map[int64]*plannerProbeState{}}
}

func (p *Planner) SetCompactionWindowResolver(fn func() int) { p.windowFn = fn }

// SetCompactor wires the cold-node compactor (cold-digest §7). Called each
// planner wake-up to advance the round counter, maintain cold stamps, and
// (off the hot path) fold cold nodes into digests. nil = feature disabled.
func (p *Planner) SetCompactor(c *Compactor) { p.compactor = c }

// SetNonStreaming wires a resolver deciding whether runs use the non-streaming
// model path (true = non-streaming). nil/unset = streaming (default).
func (p *Planner) SetNonStreaming(fn func() bool) { p.nonStreamingFn = fn }

func (p *Planner) nonStreaming() bool { return p.nonStreamingFn != nil && p.nonStreamingFn() }

// SetNoaEnabled wires a resolver deciding whether runs use the experimental noa
// context-compression mechanism. nil/unset = off (built-in compaction). Read per
// run so the settings toggle takes effect without rebuilding the agent.
func (p *Planner) SetNoaEnabled(fn func() bool) { p.noaEnabledFn = fn }

// SetMaxTokens wires a resolver for the per-reply output cap. nil/unset or 0 =
// send no cap and let the endpoint decide. Read per run, like nonStreaming.
func (p *Planner) SetMaxTokens(fn func() int) { p.maxTokensFn = fn }

func (p *Planner) maxTokens() int {
	if p.maxTokensFn == nil {
		return 0
	}
	return p.maxTokensFn()
}

func (p *Planner) compactionWindow() int {
	if p.windowFn != nil {
		return p.windowFn()
	}
	return p.window
}

// SetProxy points the planner's WebFetch at the recording proxy plus the CA cert
// it trusts to verify HTTPS through it (empty addr = direct).
func (p *Planner) SetProxy(addr, caCert string) { p.proxyAddr, p.proxyCACert = addr, caCert }

// SetUAResolver 接入按任务稳定分配的客户端 UA，供 WebFetch 请求头与 worker 共用。
func (p *Planner) SetUAResolver(fn func(taskID int64) string) { p.uaFn = fn }

func (p *Planner) uaForTask(taskID int64) string {
	if p.uaFn == nil {
		return ""
	}
	return p.uaFn(taskID)
}

// SetGuardResolver wires a per-task Guard hook resolver so the planner's
// opening probes still pass through task scope, RoE, and intercept guards.
func (p *Planner) SetGuardResolver(fn func(taskID int64) harness.HookRunner) { p.guardFn = fn }

// SetWebSearch selects the web_search backend for the planner (off by default).
func (p *Planner) SetWebSearch(o WebSearchOpts) { p.webSearch = o }

// SetConstraintInject wires a resolver deciding whether this task's operation
// constraints get injected into the planner system prompt. Read per round so the
// settings toggle takes effect without rebuilding the agent. nil = inject (default).
func (p *Planner) SetConstraintInject(fn func() bool) { p.injectConstraints = fn }

// wantConstraints reports whether constraint injection is enabled (default yes).
func (p *Planner) wantConstraints() bool { return p.injectConstraints == nil || p.injectConstraints() }

// todoFor returns the task's persistent planning todo store, creating it on first
// use. Shared across all of this task's planner wake-ups.
func (p *Planner) todoFor(expID int64) *actool.TodoStore {
	p.todoMu.Lock()
	defer p.todoMu.Unlock()
	s := p.todos[expID]
	if s == nil {
		s = actool.NewTodoStore()
		p.todos[expID] = s
	}
	return s
}

// TodoFor exposes the task's persistent planning whiteboard so the Red Team command seat shares it.
func (p *Planner) TodoFor(expID int64) *actool.TodoStore { return p.todoFor(expID) }

// probeFor returns the task's opening-probe allowance, creating it on first use.
// Shared across all of this task's planner wake-ups.
func (p *Planner) probeFor(expID int64) *plannerProbeState {
	p.probeMu.Lock()
	defer p.probeMu.Unlock()
	s := p.probes[expID]
	if s == nil {
		s = &plannerProbeState{}
		p.probes[expID] = s
	}
	return s
}

// ForgetExploration drops per-exploration in-memory planner state (todos and
// opening-probe counters) when a task is deleted or archived.
func (p *Planner) ForgetExploration(expID int64) {
	p.todoMu.Lock()
	delete(p.todos, expID)
	p.todoMu.Unlock()
	p.probeMu.Lock()
	delete(p.probes, expID)
	p.probeMu.Unlock()
}

// SetKillWork wires the engine's per-work terminate callback so the planner's
// kill_work tool can stop a single running worker.
func (p *Planner) SetKillWork(fn func(context.Context, int64) error) { p.killWork = fn }

// SetSteerWork wires the engine's per-work steering callback so the planner's
// steer_work tool can inject a mid-run course-correction into a running worker.
func (p *Planner) SetSteerWork(fn func(intentID int64, msg string) error) { p.steerWork = fn }

// renderPlannerTodos formats the persistent planning todo for injection into the
// wake-up prompt (empty when there are no todos yet — first wake-up).
func renderPlannerTodos(items []actool.Todo) string {
	if len(items) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n【你的规划待办（跨唤醒保留，上一轮你写的）】：\n")
	for _, it := range items {
		mark := map[actool.TodoStatus]string{actool.TodoPending: "☐", actool.TodoInProgress: "▶", actool.TodoCompleted: "✔"}[it.Status]
		if mark == "" {
			mark = "☐"
		}
		b.WriteString(fmt.Sprintf("  %s %s\n", mark, it.Content))
	}
	b.WriteString("据此推进：只对【前置步骤已完成 / 其依赖的 fact 已存在】的下一步派意图；仅当本轮确有步骤被满足、新增跨步杀伤链或旧链作废时才调 TodoWrite 更新（若工位已满不派单或待办状态无实质变化，严禁重复调用 TodoWrite 空刷清单）。不要重复派已在清单里 pending/in_progress 的步骤。")
	return b.String()
}

// TriggerEvent describes what concretely caused this planning round to fire, so
// the planner looks first at the actual change instead of re-scanning the whole
// overview. Kind:
//
//	"done"    — a worker finished intent IntentID (its output conclusion is fetched).
//	"finding" — a worker reported a finding on intent IntentID (Detail = 摘要).
//	"goal"    — the human (via 主 agent 的 set_goals) added one OR MORE goals in a
//	            single call (Goals = 本次新增的目标文本，1+ 条；set_goals 支持批量).
//	"goal_deleted" — the human deleted a goal from 总览的目标管理 (Detail = 被删目标文本).
//	"goal_edited"  — the human edited a goal from 总览的目标管理 (OldGoal→NewGoal 文本).
//	"cancelled" — the human deleted intent IntentID (Detail = 删除原因). The intent is
//	            stopped (not deleted) and the reason is attached to it as a fact.
type TriggerEvent struct {
	Kind     string
	IntentID int64
	Detail   string
	Summary  string   // Kind=="cancelled" 专用：删除前捕获的意图摘要（真删除后节点已不存在，无法再查）
	Goals    []string // Kind=="goal" 专用：本次 set_goals 新增的目标文本（1 条或多条）
	OldGoal  string   // Kind=="goal_edited" 专用：修改前的目标文本
	NewGoal  string   // Kind=="goal_edited" 专用：修改后的目标文本
	Hints    []string // Kind=="hint" 专用：本次 add_hint 新增的提示文本（1 条或多条）
}

// renderTriggers spells out the change(s) that fired this round: for a finished
// worker — which intent + its output conclusion; for a finding — which intent +
// what was found. Empty for time/heartbeat wakes. Reads the store (best-effort;
// a blank field never blocks the round).
func renderTriggers(ts *db.ExplorationStore, evs []TriggerEvent) string {
	if len(evs) == 0 || ts == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n【本次触发本轮的实际变动（先看这里，再决定是否补方向）】：")
	for _, ev := range evs {
		switch ev.Kind {
		case "goal":
			if len(ev.Goals) == 1 {
				b.WriteString(fmt.Sprintf("\n- 人（主 agent）新增了一个目标：%s —— 新的待达成目标，请据此补充探索方向（若尚无对应意图）。", ev.Goals[0]))
			} else {
				b.WriteString(fmt.Sprintf("\n- 人（主 agent）新增了 %d 个目标：%s —— 均为新的待达成目标，请逐一为尚无对应意图的目标补充探索方向。", len(ev.Goals), strings.Join(ev.Goals, "；")))
			}
		case "hint":
			if len(ev.Hints) == 1 {
				b.WriteString(fmt.Sprintf("\n- 人（主 agent）新增了一条战略提示：%s —— 已挂到探索图上，请据此调整/补充探索方向（若尚无对应意图）。", ev.Hints[0]))
			} else {
				b.WriteString(fmt.Sprintf("\n- 人（主 agent）新增了 %d 条战略提示：%s —— 均已挂到探索图上，请逐一据此调整/补充探索方向。", len(ev.Hints), strings.Join(ev.Hints, "；")))
			}
		case "goal_deleted":
			b.WriteString(fmt.Sprintf("\n- 人删除了该目标：%s —— 该目标已移除，请据此重判剩余目标/方向（不必再为它派意图）。", ev.Detail))
		case "goal_edited":
			b.WriteString(fmt.Sprintf("\n- 人修改了目标，由「%s」变为「%s」—— 请据新目标调整探索方向（原方向若已不适用请停派）。", ev.OldGoal, ev.NewGoal))
		case "finding":
			b.WriteString(fmt.Sprintf("\n- 意图 #%d（%s）的 worker 报告了一个 finding：%s", ev.IntentID, intentSummary(ts, ev.IntentID), WrapUntrustedData("worker-output", ev.Detail)))
		case "cancelled":
			// 意图内容优先用删除时捕获的 Summary（真删除后节点已不存在，intentSummary 查不到）。
			sm := ev.Summary
			if sm == "" {
				sm = intentSummary(ts, ev.IntentID)
			}
			b.WriteString(fmt.Sprintf("\n- 意图 #%d 由用户删除，意图内容是：%s、删除原因是：%s。该意图已删除（不再执行）；请据此重新规划。", ev.IntentID, sm, ev.Detail))
		default: // "done"
			stateTag := ""
			if n, err := ts.GetNode(ev.IntentID); err == nil && n != nil && n.State != "" {
				if n.BlockedReason != "" {
					stateTag = fmt.Sprintf(" [终态: %s, blocked_reason=%s]", n.State, n.BlockedReason)
				} else {
					stateTag = fmt.Sprintf(" [终态: %s]", n.State)
				}
			}
			b.WriteString(fmt.Sprintf("\n- 意图 #%d（%s）%s的 worker 结束，输出结论：%s", ev.IntentID, intentSummary(ts, ev.IntentID), stateTag, WrapUntrustedData("worker-output", workerOutput(ts, ev.IntentID))))
			if fids := factIDsYielded(ts, ev.IntentID); fids != "" {
				b.WriteString(fmt.Sprintf("；本意图新产生的事实 id：%s ", fids))
			}
		}
	}
	b.WriteString("\n（若意图以 exhausted / blocked 结束，先用 get_worker_trace / get_worker_output 看清实际推进到哪、卡在哪再决定续派或降权绕行。）")
	return b.String()
}

// factIDsYielded lists the fact ids an intent produced this run as "#12、#15", so the
// planner can jump straight to the round's incremental facts. Empty (best-effort) when
// the intent yielded no facts or the lookup fails.
func factIDsYielded(ts *db.ExplorationStore, id int64) string {
	ids, err := ts.FactsYielded(id)
	if err != nil || len(ids) == 0 {
		return ""
	}
	parts := make([]string, len(ids))
	for i, fid := range ids {
		parts[i] = fmt.Sprintf("#%d", fid)
	}
	return strings.Join(parts, "、")
}

// intentSummary reads an intent node's one-line summary (best-effort, "?" on miss).
func intentSummary(ts *db.ExplorationStore, id int64) string {
	n, err := ts.GetNode(id)
	if err != nil || n == nil {
		return "?"
	}
	var p map[string]any
	if json.Unmarshal(n.Payload, &p) == nil {
		if s, ok := p["summary"].(string); ok && s != "" {
			return s
		}
	}
	return "?"
}

// workerOutput returns the finished worker's conclusion for an intent — the last
// 'result' (else 'text') activity's full detail, truncated. Same source get_worker_output uses.
func workerOutput(ts *db.ExplorationStore, id int64) string {
	pick, err := ts.LatestWorkerOutput(id)
	if err != nil {
		return "(取输出失败)"
	}
	if pick == nil {
		return "(该 work 尚无输出记录)"
	}
	out := pick.Detail
	if out == "" {
		out = pick.Summary
	}
	return truncOutput(out, 800)
}

// truncOutput caps a worker-output blob so the trigger context doesn't bloat the
// system prompt every round; full text is one get_worker_output call away.
func truncOutput(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + " …（已截断，完整见 get_worker_output）"
}

// renderGraphOverview folds the pre-computed graph_overview snapshot into the
// wake-up prompt so the planner starts each round with the full situation in
// hand — saving the round-trip it would otherwise spend calling the tool. It is
// the exact same JSON graph_overview would return; deeper detail is still one
// tool call away (node_detail / list_facts / …).
func renderGraphOverview(data map[string]any) string {
	b, err := json.Marshal(data)
	if err != nil {
		return "" // fall back to the model calling graph_overview itself
	}
	return "\n\n【本轮态势（graph_overview 预取，等同你调用该工具的返回；需要细节再按需调 node_detail/list_facts 等）】：\n" + string(b)
}

// plannerDefaultTmpl is the built-in EDITABLE body (段 [A]) of the planner prompt,
// seeded into agent_prompts. Goal is a {{.Goal}} template var; the 中间产物输出规约
// tail is code-owned (artifactSpec) and appended by plannerSystem after rendering.
const plannerDefaultTmpl = `你是授权安全测试与红队行动的"红队队长 / 规划者"，负责全局情报拼图、靶面分诊（Recon Triage）、火力去冲突（Deconfliction）与目标验收。你指挥突击手（worker）作战，**绝不亲自下场挖掘或验证漏洞，也绝不把目标筛选与调度权外包给 worker**。

任务目标：{{.Goal}}

**本轮派单决策原则**：
- **防停摆底线（最高优先）**：只要【目标未达成】且【当前没有任何 open 或 running 意图】（frontier_open=0 且 running_intents 为空），本轮**必须**产出至少一个推进意图。
- 底线之外，**产出 0 个意图是正常节制**：①现有方向已被 open/running 意图覆盖（严禁换措辞重复派单）；②下一步强依赖某条在跑意图的产出。若目标未达成且存在互不依赖的未测攻击面或空闲算力，则果断拆单填满火力。

**每次唤醒的作战流程**：

1. **战况研判与跨资产拼图**（下方已预取完整 graph_overview，无需再调它空查）：
   - **情报关联**：每个意图带 parents/yields、recent_facts 带 from_intent。主攻**跨资产杀伤链拼图**——一旦发现凭据泄露、JS 隐藏路由/签名算法、SSRF 或内部代理点，务必用 parent_ids 综合关联目标资产派发高危串联意图，而不是只做孤立单点探测。
   - **高价值靶标（crown_jewels）优先**：优先推进 reached_by_finding=false 且 frontier_distance 最小或未触达的高价值靶标。
   - **否定/受阻观察核验**：negative_result 是单兵局部观察而非终局死刑：采信前调 node_detail(id) 核实 evidence。HTTP 500、异常 403、WAF 拦截或超时往往意味后端解析/过滤异味而非"目标损坏/不可解"——evidence 缺失、仅试一次、未覆盖关键端口或 confidence=inferred 一律按【尚未探明】处理，换协议/编码/利用路径派一次复核（同一否定方向至多复核一次）。
   - 按需调 list_facts / list_findings / node_detail / list_assets（全局共享，按任务范围筛选，勿盲拉全量）/ asset_neighbors。

2. **目标验收**：对已被实锤证据满足的未完成 goal 调 prove_goal(goal_id, evidence_id, reason)。标完最后一个即自动收官。
   - ⚠️ **量化目标硬核对**：目标含量化指标（覆盖率、数量等）时，必须先核对 graph_overview 实测计数，未达标严禁提前标 met。

3. **（按需，极轻量）开局靶面分诊（Recon Triage）**：
   - 当任务带外部目标账本/资产清单或仅靠图谱不足以点名具体单目标时，可用极少量只读命令做开局分诊、拉清待测对象与边缘特征（区分 CDN/WAF 共享边缘与直连源站）。**唯一合法产物是拆出锚定具体目标的精准意图**——一旦看清目标列表立刻收手派单，禁止在规划席上做注入/爆破/漏洞利用。

4. **战术拆单铁律（严禁盲盒自调度，消灭文牍空转）**：
   - **所有意图必须落入三类标准红队动作之一**：
     1) **广度侦察哨**：针对未测绘域名/资产面做存活识别、前端 JS 路由/API 与鉴权机制提取，写回 assets/fact 即停，不混装漏洞利用；
     2) **定点破袭单**：必须锁定**唯一具体目标（站点/服务/端点簇）+ 明确攻击假设**往深打穿。**严禁下发"让 worker 自己拉目标列表挑一个打、打完再换下一个补位"的自调度总包单**（会导致火力撞车、配额/WAF 踩踏与单兵上下文腐化）；
     3) **内网纵深单**：依托已登记立足点会话或隧道向高价值内网靶标横向推进。
   - **比对历史状态去重**：
     · done：看 yields 事实决定是否需要基于【实质性新机理】追加新方向，禁止换措辞重试。
     · exhausted / blocked：先看 get_worker_trace / get_worker_output：接近突破被掐断的汇总已得路径/凭据/断点续派；gateway_waf_blocked 时严禁原样重派，要求改用本地编码脚本直接发包靶机且只打精简结果（连续被拦 ≥3 次则换高价值面）。
   - **深度优先与多路并进**：拿下一条高价值入口后集中加注打穿，同时保持 2–3 条本质不同的利用链（如前端 API 越权 vs 文件处理解析 vs 认证绕过）并行试探；永远服从顶部【操作约束】。
   - **串行链与 TodoWrite 极简纪律**：TodoWrite **仅用于追踪存在严格前后置依赖的未完成跨轮次攻击链**（本轮只派前置已满足的下一步）。**若工位已满暂不派单、或待办状态无实质变更，严禁调 TodoWrite 空刷清单**。

5. **批量提交 add_intent**（每次至多 4 个最高价值意图）：
   - **summary**：明确写出【动作类型 + 唯一目标资产 + 要验证的攻击假设/关注点】。
   - **asset_ids**：凡针对具体站点/主机/端点，务必传对应 asset_ids（纯开局全局测绘才留空）。
   - **parent_ids**：综合多个线索或接力下一跳时传上游事实/发现/意图 id。
   - **从已确认侦察事实开下一跳**：必须带 parent_ids（该 fact/finding，形成 derived_from）或对应资产的 asset_ids（意图锚点），执行进场预塞才能读到这些已确认事实。既无边也无锚的新意图预塞为空；不要假设读取侧已对任意后续意图闭环。

不重复、不甩包、不空刷；以红队实战产出为唯一准绳。`

func plannerSystem(goal, dataDir, workDir string) string {
	body := renderSystem("planner", plannerDefaultTmpl, PlannerVars{Goal: goal, DataDir: dataDir, Now: nowStr()})
	return body + artifactSpec(workDir) + untrustedDataRule + plannerHoneypotRules + chainskel.PlannerMetaRules
}

// Plan runs one planning round. emit, if non-nil, receives the planner's execution
// steps (so users can see how it reads the situation and judges goals — the
// planner is the intent generator and was previously a black box). Returns whether
// the planner judged the goal met.
// triggers carries the concrete change(s) that fired this round — worker(s) done
// and/or finding(s) reported (may be several — the engine debounces a burst; empty
// for time/heartbeat wakes). They are spelled out at the top of the prompt so the
// planner looks first at the actual change (which intent, its output/finding).
func (p *Planner) Plan(ctx context.Context, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, goal string, triggers []TriggerEvent, emit func(db.Activity)) (met bool, reason string, err error) {
	// cold-digest §2.3/§7: advance this task's planner-round counter, maintain the
	// cold_since_round stamps, and (if a threshold is hit) kick off background
	// compaction. Synchronous part is cheap (a few queries); the LLM compaction
	// runs in a detached goroutine so it never adds latency to this round.
	p.compactor.OnPlannerRound(ctx, ts)
	tsx := NewToolSet(ts, "planner")
	tsx.SetFindingRecorder(p.findingRecorder)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(taskID)
	tsx.SetCoverageEnabled(as == nil || as.CoverageEnabled(taskID))
	tsx.killWork = p.killWork   // enable kill_work tool (nil = unavailable)
	tsx.steerWork = p.steerWork // enable steer_work tool (nil = unavailable)
	if origin, _ := ts.OriginFactID(); origin > 0 {
		tsx.SetOwnerNode(origin) // planner-side anchors default to the task root (origin fact)
	}
	// 领域工具 + 基础默认工具集（Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash）
	// Bash/WebFetch 仍在集合里(开局极轻量探测要用),但由 plannerProbeHooks 按提示词里
	// 那三条硬边界在 harness 层兜底:有 worker 事实后禁用、开局额度 PlannerProbeLimit 封顶。
	// 资产覆盖度功能关闭时剔除 add_task_scope/list_untested_assets（不入 prompt）。
	base := append(tsx.DropCoverageTools(tsx.PlannerTools()), defaultToolsExcept()...)
	ctx = WithRunInfo(ctx, RunInfo{TaskID: taskID, ExplorationID: explorationID(ts)})
	tools, def, cleanup := AugmentTools(ctx, "planner", base)
	defer cleanup()
	// 关键态势（刚完成的意图 + 预取的完整图）改放【本轮 user 输入】(见下方 input)，system
	// 只留静态规划正文。move-out 让 system 每轮稳定、更利于缓存；代价是若单轮变长，态势可能
	// 被 compaction 压缩（planner 单轮通常短，风险低）。situational 会拼进下方 input。
	situational := renderTriggers(ts, triggers) + renderGraphOverview(tsx.graphOverviewData())
	// 任务级 deadline / 终局模式(经 ctx 注入,见 taskclock.go)。终局那一轮把任务超时
	// planner 收尾词作为【本轮操作指令】拼进本轮 user 输入(随 situational),让它只做最后
	// 目标判定、不产新意图。
	tc := taskClockFrom(ctx)
	if tc.Final {
		situational += "\n\n【任务终局收尾（本轮特殊指令，覆盖上面的常规规划流程）】：" + resolveTaskTimeoutWrapup("planner")
	}
	// 本任务的工作目录 <workDir>/tasks/<taskID>，先建好。
	// shared/ 给跨单兵制品（密钥、路由表、字典）；worker 私有文件在 i<意图id>/。
	taskDir := ensureRunDir(p.workDir, taskID, 0)
	ensureTaskSharedDir(taskDir)
	ctx = intercept.WithReviewContext(ctx, taskDir, intercept.ReviewBackground{})
	sysBody := plannerSystem(goal, p.workDir, taskDir)
	if p.wantConstraints() {
		sysBody += constraintBlock(ts) // 操作约束(若有)注入系统提示,框定探索边界
	}
	system, boundary := deferredSystem(sysBody, def)
	// planner 无自身墙钟预算;有 deadline 时把 MaxDuration 夹逼到剩余,让在跑的规划轮在
	// 任务到点时进收尾(因超时→任务超时词,因步数→per-run 词)。
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, 0)
	settle := wrapupSettlement("planner", nil)
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("planner", nil, clamped)
	}
	window := p.compactionWindow()
	opts := agentcore.Options{
		Provider:        p.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  true, // 走记录代理留痕；载入代理 CA 验证 MITM 重签的 HTTPS 证书
		WebFetchProxy:   p.proxyAddr,
		WebFetchCACert:  p.proxyCACert,
		// 联网搜索(可选)。ddgs 无需 key；brave-free 需 BraveKey；tavily 需 TavilyKey。
		// WebSearchProxy 是独立出口代理(http/https/socks5)，与记录流量的 MITM 代理无关；空则直连。
		EnableWebSearch:       p.webSearch.Enabled,
		WebSearchBackend:      p.webSearch.Backend,
		BraveSearchAPIKey:     p.webSearch.BraveKey,
		TavilySearchAPIKey:    p.webSearch.TavilyKey,
		DeepSeekSearchBaseURL: p.webSearch.DeepSeekBaseURL,
		DeepSeekSearchAPIKey:  p.webSearch.DeepSeekAPIKey,
		DeepSeekSearchModel:   p.webSearch.DeepSeekModel,
		WebSearchProxy:        p.webSearch.Proxy,
		BashEnv:               shellEnv(p.workDir, proxyEnv(p.proxyAddr, p.proxyCACert)), // Bash 子命令默认走代理+信任 CA
		WorkingDir:            taskDir,                                                   // 本任务工作目录 <workDir>/tasks/<taskID>
		ToolOutputDir:         cmdOutDir(taskDir),
		MaxTurns:              p.maxTurns, // 0 = unlimited (configurable in agent management)
		MaxDuration:           maxDur,     // 0=不限;有 deadline 时=距 deadline 剩余
		Compaction:            compactionConfig(window),
		// 跨唤醒共享的规划待办：让串行链在多轮之间保留（session 是新的，store 不是）。
		Todos: p.todoFor(ts.ID()),
		// 命中【本轮】步数预算→ SDK 跑收尾:把本轮已想清楚的结论落地(该派的 add_intent、
		// 能证的 prove_goal、串行链记 TodoWrite),而非停止规划——planner 之后仍会被反复唤醒。
		// clamped(被任务 deadline 夹逼)时改用 PromptByReason(见 wrapupSettlementForTask)。
		Settlement:   settle,
		NonStreaming: p.nonStreaming(), // 该 profile 选非流式时走 Provider.Complete
		MaxTokens:    p.maxTokens(),    // 0 = 不发上限,由服务端默认值决定
	}
	AttachStableWebFetch(&opts, p.uaForTask(taskID))
	// 默认摘除 plannerProbeHooks 硬拦截（保留 Guard/RoE/Intercept 内层钩子），恢复 e6ec5699
	// 中规划者读取平台/靶场账本的能力；如需强制代码级探针上限可显式设 ARTEX_ENABLE_PLANNER_PROBE_GUARD=1。
	var innerHooks harness.HookRunner
	if p.guardFn != nil {
		innerHooks = p.guardFn(taskID)
	}
	opts.Hooks = innerHooks
	if envBoolFlag("ARTEX_ENABLE_PLANNER_PROBE_GUARD", false) {
		opts.Hooks = WrapPlannerProbe(innerHooks, p.probeFor(ts.ID()), PlannerProbeLimit, func() (int, bool) {
			n, err := ts.CountWorkerFacts()
			if err != nil {
				return 0, false // fail soft: never guess the graph is empty
			}
			if n > 0 {
				return n, true
			}
			f, err := ts.CountByKind(db.KindFinding)
			if err != nil {
				return 0, false
			}
			return f, true
		})
	}
	if p.tx != nil { // persist raw LLM conversation; one accumulating file per task's planner
		opts.Transcript = p.tx
		opts.SessionID = fmt.Sprintf("exp%d-planner", ts.ID())
	}
	// 实验功能:开启后由 noa 接管上下文压缩(归档集中在 <workDir>/noa/<SessionID> 下,持久)。
	noaSession := fmt.Sprintf("exp%d-planner", ts.ID())
	installRuntimeCompactor(&opts, ts)
	enableNoa(&opts, p.noaEnabledFn, p.workDir, noaSession, window, noaWarn(noaSession))
	attachToolOutputSpilling(&opts)
	// 态势（刚完成的意图 + 完整图）现在拼进本轮 user 输入（见下方 input）。user 里还有
	// 指令 + 跨唤醒待办（todo 是模型自己的规划便签，可再生，放 user 即可）。
	// 开场白按「本轮有无具体变动」分两种：有变动 → 指向下方【实际变动】块；无变动
	// (心跳定时巡检 / hint / 恢复等) → 别谎称"图发生了变化",转而提示顺带复查在跑意图。
	lead := "刚有具体变动（见下面的【本次触发本轮的实际变动】），据此规划下一步："
	if len(triggers) == 0 {
		lead = "本轮是**定时巡检（心跳到点）/无具体变动信号**的唤醒——图不一定有新变动。顺带复查在跑意图：长时间无进展或跑偏的用 steer_work 纠偏、方向整个错的用 kill_work 止损；再判定目标、决定是否补方向："
		// 心跳/无变动唤醒时,若全图已无任何 open 或 running 意图 → 探索已停摆(没 worker 在跑、
		// 也没排队方向)。明确告知 planner 并强制其本轮补出新方向,别只复查在跑意图后空转一轮。
		if active, err := ts.HasActiveIntent(); err == nil && !active {
			lead = "本轮是**定时巡检（心跳到点）**的唤醒,且当前**已没有任何 open 或 running 的意图**——没有 worker 在跑、也没有排队中的方向,探索已停摆。你**必须**在本轮产出一个或多个向目标推进、且与图中既有意图**互不重复**的新意图(不得产出 0 意图);先据下面的态势判定目标是否已达成,未达成则立即补方向："
		}
	}
	input := lead + situational + "\n\n据上面的态势，判定目标。目标已【真正达成】（已拿到目标成果/已确认目标漏洞）时用 prove_goal 逐个标记。**硬底线：只要目标尚未达成、且当前没有任何 open 或 running 意图（frontier_open=0 且 running_intents 为空），本轮就必须产出至少一个向目标推进的意图——此时没有在跑的 work 可等、也没有在排队的方向，产出 0 意图=任务停摆。仅当已有 open/running 意图在推进、或目标已达成时，本轮才可以不产出新意图。**" +
		renderPlannerTodos(opts.Todos.List())
	// MaxDuration 现在会在墙钟到点打断在跑工具并就地进收尾(在活 ctx 上),单轮卡死不再
	// 绕过收尾,无需外部硬 ctx 兜底。ctx 只承载 pause / kill / shutdown。
	_, _, err = captureRun(ctx, opts, input,
		func(r db.Activity) {
			if emit != nil {
				r.Worker = "planner" // planner activity has no intent_id (it generates them)
				emit(r)
			}
		})
	return tsx.GoalMet, tsx.Reason, err
}
