package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

// MainAgent is the human-facing Red Team Lead command seat: it shares the
// planner's whiteboard (TodoStore), kill/steer/goal-proof authority, RoE guards,
// and live graph_overview snapshot so operators talk directly to command instead of
// relaying through a decoupled liaison.
type MainAgent struct {
	findingRecorder    FindingRecorder
	prov               llm.Provider
	model              string
	tx                 *transcript.Store                      // raw LLM conversation persistence (nil = off)
	window             int                                    // context window in tokens (for compaction)
	windowFn           func() int                             // optional dynamic task-chain minimum
	maxTurns           int                                    // max agent turns per run (0 = unlimited)
	proxyAddr          string                                 // recording proxy for WebFetch (empty = direct)
	proxyCACert        string                                 // recording proxy's CA cert path (HTTPS verify)
	webSearch          WebSearchOpts                          // web_search tool backend selection (off by default)
	workDir            string                                 // shared work dir (surfaced in prompt as artifact-output target)
	steerWork          func(intentID int64, msg string) error // engine callback: steer a running work (nil = off)
	killWork           func(context.Context, int64) error     // engine callback: terminate a running work (nil = off)
	todoFn             func(expID int64) *actool.TodoStore    // shared whiteboard with Planner (nil = local ephemeral)
	guardFn            func(taskID int64) harness.HookRunner  // per-task Guard/RoE hooks (shared with Planner/Worker)
	constraintInjectFn func() bool                            // inject task operation constraints? (nil = yes)
	nonStreamingFn     func() bool                            // resolver: use non-streaming (Complete) path? (nil = streaming)
	noaEnabledFn       func() bool                            // resolver: use experimental noa compaction? (nil = off)
	maxTokensFn        func() int                             // resolver: per-reply output cap (nil/0 = send no cap)
	uaFn               func(taskID int64) string              // 按任务稳定 UA → WebFetch 请求头；nil = 官方默认
}

// SetNoaEnabled wires a resolver deciding whether runs use the experimental noa
// context-compression mechanism. nil/unset = off (built-in compaction). Read per
// run so the settings toggle takes effect without rebuilding the agent.
func (m *MainAgent) SetNoaEnabled(fn func() bool) { m.noaEnabledFn = fn }

// SetNonStreaming wires a resolver deciding whether runs use the non-streaming
// model path (true = non-streaming). nil/unset = streaming (default).
func (m *MainAgent) SetNonStreaming(fn func() bool) { m.nonStreamingFn = fn }

func (m *MainAgent) nonStreaming() bool { return m.nonStreamingFn != nil && m.nonStreamingFn() }

// SetMaxTokens wires a resolver for the per-reply output cap. nil/unset or 0 =
// send no cap and let the endpoint decide. Read per run, like nonStreaming.
func (m *MainAgent) SetMaxTokens(fn func() int) { m.maxTokensFn = fn }

func (m *MainAgent) maxTokens() int {
	if m.maxTokensFn == nil {
		return 0
	}
	return m.maxTokensFn()
}

func NewMainAgent(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *MainAgent {
	return &MainAgent{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns}
}

func (m *MainAgent) SetCompactionWindowResolver(fn func() int) { m.windowFn = fn }

func (m *MainAgent) compactionWindow() int {
	if m.windowFn != nil {
		return m.windowFn()
	}
	return m.window
}

// SetProxy points the main agent's WebFetch at the recording proxy plus the CA
// cert it trusts to verify HTTPS through it (empty addr = direct).
func (m *MainAgent) SetProxy(addr, caCert string) { m.proxyAddr, m.proxyCACert = addr, caCert }

// SetUAResolver 接入按任务稳定分配的客户端 UA，供 WebFetch 请求头与 worker 共用。
func (m *MainAgent) SetUAResolver(fn func(taskID int64) string) { m.uaFn = fn }

func (m *MainAgent) uaForTask(taskID int64) string {
	if m.uaFn == nil {
		return ""
	}
	return m.uaFn(taskID)
}

// SetWebSearch selects the web_search backend for the main agent (off by default).
func (m *MainAgent) SetWebSearch(o WebSearchOpts) { m.webSearch = o }

// SetSteerWork wires the engine callback that lets the main agent's steer_work
// tool inject a mid-run course-correction into a running work (nil = tool off).
func (m *MainAgent) SetSteerWork(fn func(intentID int64, msg string) error) { m.steerWork = fn }

// SetKillWork wires the engine's per-work terminate callback so the command seat can stop a running worker.
func (m *MainAgent) SetKillWork(fn func(context.Context, int64) error) { m.killWork = fn }

// SetTodoResolver binds MainAgent to Planner's persistent per-exploration TodoStore whiteboard.
func (m *MainAgent) SetTodoResolver(fn func(expID int64) *actool.TodoStore) { m.todoFn = fn }

// SetGuardResolver wires per-task Guard/RoE hooks onto the command seat.
func (m *MainAgent) SetGuardResolver(fn func(taskID int64) harness.HookRunner) { m.guardFn = fn }

// SetConstraintInject wires the task operation-constraint toggle (nil = inject).
func (m *MainAgent) SetConstraintInject(fn func() bool) { m.constraintInjectFn = fn }

func (m *MainAgent) wantConstraints() bool { return m.constraintInjectFn == nil || m.constraintInjectFn() }

// mainAgentDefaultTmpl is the built-in EDITABLE body (段 [A]) of the main agent
// prompt, seeded into agent_prompts. Goal is a {{.Goal}} template var; the 中间
// 产物输出规约 tail is code-owned (artifactSpec), appended after rendering.
const mainAgentDefaultTmpl = `你是本任务的"红队队长"人机直通指挥席（主 agent），与后台自动规划共享同一套探索图谱、杀伤链待办白板与火力控制权。系统提示末尾已实时附上当前全局态势与待办白板，无需开局再调 graph_overview 空查。职责：

1. **战况研判与复盘**：基于实时态势，按需调 node_detail / list_facts / list_findings / get_worker_output / list_assets 直答指挥官关于战局与证据的提问，绝不编造未实测的结论。
2. **直接指挥与火力调配（少当传声筒，能直接落地的当场执行）**：
   - 叫停跑偏/卡死突击手 → 直接调 kill_work；对在跑突击手递话微调打法 → 调 steer_work（先看 get_worker_output）；
   - 指派具体侦察或突破任务 → 直接调 add_intent 下发【单目标明确假设】的高优意图（priority 8-10，必传关联 asset_ids / parent_ids，严禁下发多目标盲盒总包单）。系统会自动把已完成任务拉回运行态执行，跑完即回已完成状态；
     **当任务目标已全部达成时**（graph_overview 里 goals 均为 met）：下发前先判断该意图背后是否隐含"新的正式目标"。若隐含，先用一句话复述确认是否登记为正式目标（要 → set_goals 接续自动推进；不要/仅临时查证 → 只 add_intent 下发这一条）；明显只是一次性查证则直接 add_intent；
   - 调整授权边界与红线 → 增删测试范围调 add_task_scope（支持 root_domain / subdomain / ip / cidr 及 exclude_root_domain / exclude_subdomain / exclude_ip / exclude_cidr 反向排除），增改操作禁令调 set_constraints；
   - 维护跨步杀伤链或长期战略方针 → 跨步依赖链直接更新共享 TodoWrite 白板；需持续贯穿后续多轮自动规划的战略偏好再用 add_hint 留存；
   - 增补或核销目标 → 新增正式目标用 set_goals（会自动把已完成/暂停任务拉回运行态继续）；目标已被实锤证据满足时可调 prove_goal 核销。
3. 用简练红队语言汇报你实际执行的指挥动作与当前火力布局。

当前任务目标：{{.Goal}}

不要编造发现；只根据工具返回的真实数据回答。`

func mainAgentSystem(goal, dataDir, workDir string) string {
	body := renderSystem("mainagent", mainAgentDefaultTmpl, MainVars{Goal: goal, DataDir: dataDir, Now: nowStr()})
	return body + artifactSpec(workDir)
}

// Chat handles one human message and returns the assistant reply. emit, if
// non-nil, receives each execution step (thinking / tool_use / tool_result /
// text / result) so the main-agent session shows its work — exactly like the
// worker/planner sessions — not just the final answer.
func (m *MainAgent) Chat(ctx context.Context, taskID int64, mainSeg int, as *db.AssetStore, ts *db.ExplorationStore, goal, message string, emit func(db.Activity), notify, resume func(), notifyGoal, notifyHint func([]string)) (string, error) {
	return m.runChat(ctx, taskID, mainSeg, as, ts, goal, message, m.maxTurns, 0, emit, notify, resume, notifyGoal, notifyHint)
}

// Patrol runs one autonomous campaign-orchestration round on the shared mainagent
// transcript without emitting a synthetic human user activity row. It stays bounded
// by patrolMaxTurns (default 12) and patrolMaxDur (default 4m).
func (m *MainAgent) Patrol(ctx context.Context, taskID int64, mainSeg int, as *db.AssetStore, ts *db.ExplorationStore, goal, triggerPrompt string, maxTurns int, maxDur time.Duration, emit func(db.Activity), notify, resume func(), notifyGoal, notifyHint func([]string)) (string, error) {
	if maxTurns <= 0 {
		maxTurns = 12
	}
	if maxDur <= 0 {
		maxDur = 4 * time.Minute
	}
	return m.runChat(ctx, taskID, mainSeg, as, ts, goal, triggerPrompt, maxTurns, maxDur, emit, notify, resume, notifyGoal, notifyHint)
}

func (m *MainAgent) runChat(ctx context.Context, taskID int64, mainSeg int, as *db.AssetStore, ts *db.ExplorationStore, goal, message string, maxTurns int, maxDur time.Duration, emit func(db.Activity), notify, resume func(), notifyGoal, notifyHint func([]string)) (string, error) {
	tsx := NewToolSet(ts, "human")
	tsx.SetFindingRecorder(m.findingRecorder)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(taskID)
	tsx.SetCoverageEnabled(as == nil || as.CoverageEnabled(taskID))
	tsx.SetNotify(notify)         // 通用唤醒（无专用回调的写操作走它，debounced）
	tsx.SetResumeTask(resume)     // set_goals 新增目标 → 把已完成/暂停的任务拉回 running
	tsx.SetNotifyGoal(notifyGoal) // set_goals 新增目标 → 给 planner 记一条「人新增了目标：…」触发
	tsx.SetNotifyHint(notifyHint) // add_hint 新增提示 → 给 planner 记一条「人新增了 N 条战略提示：…」触发
	tsx.steerWork = m.steerWork // enable steer_work tool (nil = unavailable)
	tsx.killWork = m.killWork   // enable kill_work tool (nil = unavailable)
	// 领域工具 + 基础默认工具集（Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash）
	// 资产覆盖度功能关闭时剔除 add_task_scope/list_untested_assets（不入 prompt）。
	base := append(tsx.DropCoverageTools(tsx.MainAgentTools()), defaultToolsExcept()...)
	ctx = WithRunInfo(ctx, RunInfo{TaskID: taskID, ExplorationID: explorationID(ts)})
	tools, def, cleanup := AugmentTools(ctx, "mainagent", base)
	defer cleanup()
	todos := actool.NewTodoStore()
	if ts != nil && ts.ID() > 0 && m.todoFn != nil {
		todos = m.todoFn(ts.ID())
	}
	// 本任务的工作目录 <workDir>/tasks/<taskID>，先建好。
	mainDir := ensureRunDir(m.workDir, taskID, 0)
	ctx = intercept.WithReviewWorkingDirectory(ctx, mainDir)
	sysBody := mainAgentSystem(goal, m.workDir, mainDir)
	if ts != nil && m.wantConstraints() {
		sysBody += constraintBlock(ts)
	}
	if ts != nil {
		sysBody += renderGraphOverview(tsx.graphOverviewData()) + renderPlannerTodos(todos.List())
	}
	system, boundary := deferredSystem(sysBody, def)
	window := m.compactionWindow()
	opts := agentcore.Options{
		Provider:        m.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  true, // 走记录代理留痕；载入代理 CA 验证 MITM 重签的 HTTPS 证书
		WebFetchProxy:   m.proxyAddr,
		WebFetchCACert:  m.proxyCACert,
		// 联网搜索(可选)。ddgs 无需 key；brave-free 需 BraveKey；tavily 需 TavilyKey。
		// WebSearchProxy 是独立出口代理(http/https/socks5)，与记录流量的 MITM 代理无关；空则直连。
		EnableWebSearch:       m.webSearch.Enabled,
		WebSearchBackend:      m.webSearch.Backend,
		BraveSearchAPIKey:     m.webSearch.BraveKey,
		TavilySearchAPIKey:    m.webSearch.TavilyKey,
		DeepSeekSearchBaseURL: m.webSearch.DeepSeekBaseURL,
		DeepSeekSearchAPIKey:  m.webSearch.DeepSeekAPIKey,
		DeepSeekSearchModel:   m.webSearch.DeepSeekModel,
		WebSearchProxy:        m.webSearch.Proxy,
		BashEnv:               shellEnv(m.workDir, proxyEnv(m.proxyAddr, m.proxyCACert)), // Bash 子命令默认走代理+信任 CA
		WorkingDir:            mainDir,                                                   // 本任务工作目录 <workDir>/tasks/<taskID>
		ToolOutputDir:         cmdOutDir(mainDir),
		MaxTurns:              maxTurns,
		MaxDuration:           maxDur,
		Compaction:            compactionConfig(window), // long chats stay within the window
		Todos:                 todos,                    // 与红队队长/Planner 共享的任务级杀伤链白板
		// 命中预算(步数)→ SDK 跑收尾:向用户输出一句进展总结。Prompt 与收尾轮数可后台编辑(默认 10 轮)。
		Settlement:   wrapupSettlement("mainagent", nil),
		NonStreaming: m.nonStreaming(), // 该 profile 选非流式时走 Provider.Complete
		MaxTokens:    m.maxTokens(),    // 0 = 不发上限,由服务端默认值决定
	}
	AttachStableWebFetch(&opts, m.uaForTask(taskID))
	if m.guardFn != nil {
		opts.Hooks = m.guardFn(taskID)
	}
	if m.tx != nil { // persist raw human↔AI conversation; one accumulating file per segment
		opts.Transcript = m.tx
		// Segment 0 keeps the legacy "exp%d-main" name so existing transcripts still
		// load; each new session (seg>=1) gets its own file for a clean context.
		opts.SessionID = fmt.Sprintf("exp%d-main", ts.ID())
		if mainSeg > 0 {
			opts.SessionID = fmt.Sprintf("exp%d-main-s%d", ts.ID(), mainSeg)
		}
	}
	// 实验功能:开启后由 noa 接管上下文压缩(归档集中在 <workDir>/noa/<SessionID> 下,持久)。
	// session id 与 transcript 同规则(分段感知),使归档与恢复对齐。
	noaSession := fmt.Sprintf("exp%d-main", ts.ID())
	if mainSeg > 0 {
		noaSession = fmt.Sprintf("exp%d-main-s%d", ts.ID(), mainSeg)
	}
	installRuntimeCompactor(&opts, ts)
	enableNoa(&opts, m.noaEnabledFn, m.workDir, noaSession, window, noaWarn(noaSession))
	attachToolOutputSpilling(&opts)
	ctx = attachSideCapture(ctx, &opts)
	s := agentcore.NewSession(opts)
	defer s.Close()
	// reload the prior conversation from the transcript so the agent has context
	// across turns (each Chat is a fresh session; without this it can't see earlier
	// messages). First turn: no file yet → Resume loads nothing and proceeds.
	if m.tx != nil {
		message = resumeHistory(s, opts.SessionID, "mainagent", emit) + message
	}
	// C2: this session is fresh each turn; re-unlock skill-gated MCPs from prior
	// Skill() calls in the reloaded history so revealed tools stay callable.
	seedUnlockFromHistory(s.Messages(), def.UnlockSkill)
	emitMain := func(r db.Activity) {
		if emit != nil {
			r.Worker = "mainagent"
			emit(r)
		}
	}
	text, _, err := captureRunSession(ctx, s, message, emitMain)
	// 若主 Agent 长会话因上游网关 Cloudflare/WAF HTTP 403 被拦截，幂等脱敏尾部敏感载荷并自愈续跑 1 次，
	// 防止历史记录被单次载荷永久毒化。
	if err != nil && IsGatewayWAFBlock(err) && m.tx != nil && opts.SessionID != "" && ctx.Err() == nil {
		if scrubbed, scrubErr := SanitizeTranscriptTailForWAF(m.tx, opts.SessionID); scrubErr == nil && scrubbed {
			s2 := agentcore.NewSession(opts)
			defer s2.Close()
			retryMsg := resumeHistory(s2, opts.SessionID, "mainagent", emit) +
				"上一步工具输入或输出因触发上游 LLM 网关 HTTP 403 WAF 拦截已自动脱敏折叠。请勿再明文输出完整 CVE 模板、原型链或攻击载荷原文；改用本地脚本结合编码或分片直接向靶机发包并只打印精简结果，继续当前任务。"
			seedUnlockFromHistory(s2.Messages(), def.UnlockSkill)
			text, _, err = captureRunSession(ctx, s2, retryMsg, emitMain)
		}
	}
	return text, err
}
