package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

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

// Worker is an LLM work agent (docs §4.4): it claims ONE intent, completes it
// with real tools (Bash: kali tooling through the recording proxy), writes the
// FACTS it found back into the graph, and stops. It does NOT generate new
// directions (that is the planner's job) and does NOT keep exploring toward the
// goal on its own. Multiple workers run concurrently as goroutines.
// WebSearchOpts is the web-search backend selection the server pushes into each
// agent (planner/worker/main). Enabled=false leaves the web_search tool off.
// Backend is "ddgs" (no key), "brave-free" (BraveKey required), "tavily"
// (TavilyKey required), or "deepseek" (DeepSeek* required, filled from the
// active LLM profile). It maps directly onto agentcore.Options.
// Proxy is a dedicated egress proxy for the search request (http/https/socks5),
// independent of the traffic-recording MITM proxy — set it when the search endpoint
// is only reachable via a VPN/SOCKS proxy. Empty = direct.
//
// 注意 deepseek 后端与其它三个的性质不同：DeepSeek 没有可直接调用的搜索接口，
// 搜索只存在于其 Anthropic 兼容 messages 接口内部(web_search_20250305 server
// tool)，因此每次搜索会消耗一次模型调用，且搜索请求由 DeepSeek 服务端发出——
// 不经过本机 Proxy，也不会进流量留痕。
type WebSearchOpts struct {
	Enabled   bool
	Backend   string
	BraveKey  string
	TavilyKey string
	Proxy     string
	// DeepSeek* 来自当前激活的 LLM 配置(仅 anthropic 格式的 DeepSeek 官方端点)，
	// 不单独配置，随 LLM 配置切换而变。
	DeepSeekBaseURL string
	DeepSeekAPIKey  string
	DeepSeekModel   string
}

type Worker struct {
	findingRecorder FindingRecorder
	prov            llm.Provider
	model           string
	workDir         string
	proxyAddr       string
	proxyCACert     string            // recording proxy's CA cert path (for WebFetch HTTPS verify)
	webSearch       WebSearchOpts     // web_search tool backend selection (off by default)
	tx              *transcript.Store // raw LLM conversation persistence (nil = off)
	window          int               // context window in tokens (for compaction)
	windowFn        func() int        // optional dynamic task-chain minimum
	maxTurns        int               // max agent turns per run (0 = unlimited)
	// runTimeout is the wall-clock budget for the main exploration of one intent
	// (0 = unlimited). When it fires, the run is cut and a settlement round is
	// forced so already-identified facts get written back instead of being lost.
	runTimeout    time.Duration
	settleTimeout *time.Duration
	// extraTools are host-provided tools (e.g. traffic query, oast) appended to
	// the worker's graph write-back tools.
	extraTools []actool.CoreTool
	// injectConstraints resolves whether this task's operation constraints get
	// injected into the worker system prompt. Read per run so the settings toggle
	// takes effect without rebuilding the agent. nil = inject (default).
	injectConstraints func() bool
	// nonStreamingFn resolves whether this run uses the non-streaming (Complete)
	// path. Read per run so a profile/task toggle takes effect without rebuilding
	// the agent. nil = streaming (default).
	nonStreamingFn func() bool
	// noaEnabledFn resolves whether this run uses the experimental noa context-
	// compression mechanism. Read per run, like nonStreaming. nil = off (built-in
	// compaction).
	noaEnabledFn func() bool
	// maxTokensFn resolves the per-reply output cap in tokens, on the same
	// per-run basis. nil or 0 = send no cap and let the endpoint decide.
	maxTokensFn func() int
	// taskProxyFn, when set, resolves the task's own MITM instance. Empty addr
	// falls back to proxyAddr/proxyCACert so tasks cannot stomp a shared upstream.
	taskProxyFn func(taskID int64) (addr, caCert string)

	// intranetFn resolves whether a task is in its intranet phase (存在存活立足点
	// 会话)。为 true 时 worker 系统提示追加 worker.intranet 短纪律变体。
	// 每次 run 现查,会话状态变化即时生效;nil = 外网(默认)。
	intranetFn  func(taskID int64) bool
	footprintFn func(taskID int64) FootprintToggles

	// uaFn 解析本任务稳定分配的客户端 UA,经 BashEnv 注入 ARTEX_UA。
	// 同一任务始终同一个 UA;nil = 不注入。
	uaFn func(taskID int64) string

	// credentialSeedFn 每次 run 渲染继承凭据线索。nil、空串或查询失败都不改变系统提示。
	credentialSeedFn func(ctx context.Context, taskID int64) string
}

// WorkerSessionID returns the stable transcript key used by a worker intent.
// Worker slots are reusable, so the intent id (rather than work#N) is the
// session identity. Keep this helper public so the Worker message API and UI
// can refer to exactly the conversation that will be resumed.
func WorkerSessionID(explorationID, intentID int64) string {
	return fmt.Sprintf("exp%d-worker-i%d", explorationID, intentID)
}

const workerChatMarkerPrefix = "<!-- ARTEX_WORKER_CHAT:"

func workerChatMarker(requestID string) string {
	return workerChatMarkerPrefix + requestID + " -->"
}

func hasWorkerChatMessage(messages []llm.Message, requestID string) bool {
	marker := workerChatMarker(requestID)
	for _, message := range messages {
		if message.Role == llm.RoleUser && strings.Contains(message.Text(), marker) {
			return true
		}
	}
	return false
}

// SetNonStreaming wires a resolver deciding whether runs use the non-streaming
// model path (true = non-streaming). nil/unset = streaming (default). Read per
// run so a profile or task-chain toggle takes effect without rebuilding.
func (w *Worker) SetNonStreaming(fn func() bool) { w.nonStreamingFn = fn }

func (w *Worker) nonStreaming() bool { return w.nonStreamingFn != nil && w.nonStreamingFn() }

// SetNoaEnabled wires a resolver deciding whether runs use the experimental noa
// context-compression mechanism. nil/unset = off (built-in compaction). Read per
// run so the settings toggle takes effect without rebuilding the agent.
func (w *Worker) SetNoaEnabled(fn func() bool) { w.noaEnabledFn = fn }

// SetMaxTokens wires a resolver for the per-reply output cap. nil/unset or 0 =
// send no cap and let the endpoint decide. Read per run, like nonStreaming.
func (w *Worker) SetMaxTokens(fn func() int) { w.maxTokensFn = fn }

func (w *Worker) maxTokens() int {
	if w.maxTokensFn == nil {
		return 0
	}
	return w.maxTokensFn()
}

// SetIntranetResolver wires a resolver deciding whether a task runs in its
// intranet phase (追加 worker.intranet 短纪律变体)。nil/unset = 外网(默认)。
// 每次 run 现查,与 nonStreaming 一样不缓存。
func (w *Worker) SetIntranetResolver(fn func(taskID int64) bool) { w.intranetFn = fn }

func (w *Worker) intranetForTask(taskID int64) bool {
	return w.intranetFn != nil && w.intranetFn(taskID)
}

func (w *Worker) SetFootprintResolver(fn func(taskID int64) FootprintToggles) {
	w.footprintFn = fn
}

func (w *Worker) footprintForTask(taskID int64) FootprintToggles {
	if w.footprintFn == nil {
		return DefaultFootprint()
	}
	return w.footprintFn(taskID)
}

// SetUAResolver 接入按任务稳定分配的客户端 UA。每次 run 现查,任务内不更换。
func (w *Worker) SetUAResolver(fn func(taskID int64) string) { w.uaFn = fn }

func (w *Worker) uaForTask(taskID int64) string {
	if w.uaFn == nil {
		return ""
	}
	return w.uaFn(taskID)
}

// SetCredentialSeed 接入继承凭据线索。每次 run 现查；返回空串或未设置时不改系统提示。
// 解析失败由调用方吞掉并返回空串，不阻断 worker。
func (w *Worker) SetCredentialSeed(fn func(ctx context.Context, taskID int64) string) {
	if w == nil {
		return
	}
	w.credentialSeedFn = fn
}

func (w *Worker) credentialSeedBlock(ctx context.Context, taskID int64) string {
	if w == nil || w.credentialSeedFn == nil {
		return ""
	}
	return w.credentialSeedFn(ctx, taskID)
}

// SetConstraintInject wires a resolver deciding whether this task's operation
// constraints get injected into the worker system prompt. nil = inject (default).
func (w *Worker) SetConstraintInject(fn func() bool) { w.injectConstraints = fn }

// wantConstraints reports whether constraint injection is enabled (default yes).
func (w *Worker) wantConstraints() bool { return w.injectConstraints == nil || w.injectConstraints() }

// SetRunTimeout configures the per-intent wall-clock SAFETY CEILING for the main
// exploration (0 = unlimited). The default 20 minutes (run_seconds=1200) is a cap,
// not the primary "stop when the clock hits 20m" policy — stop-loss may end the
// run earlier when there are no new facts/assets or a command is repeated.
// When the ceiling does fire, the SDK settlement phase still runs so facts are
// never lost to a timeout. Safe to call before Execute.
func (w *Worker) SetRunTimeout(run time.Duration) {
	w.runTimeout = run
}

func (w *Worker) SetSettleTimeout(reserve time.Duration) {
	w.settleTimeout = &reserve
}

// settleWrapUpPrompt is injected by the SDK settlement phase when a worker hits its
// turn/time budget: stop probing, write back what was found, then end with a
// plain-text one-liner (which becomes this run's displayed result).
const settleWrapUpPrompt = "当前为纯写库结算轮，Bash 已卸载，请直接调 record_fact / report_finding / insert_assets，不要再调用 Bash。你即将因预算耗尽被终止。不要再运行任何命令/探测。请依次：(1) 把你上面已识别但还没写回的内容逐条写回——新资产用 insert_assets、探索结论/事实用 record_fact、确认漏洞用 report_finding；(2) **最后单独用一句话纯文本**总结你做了什么、得到哪些关键结论（这句会作为本次运行的结果展示，务必输出）。"

func NewWorker(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int, extra ...actool.CoreTool) *Worker {
	return &Worker{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, extraTools: extra}
}

// defaultToolsExcept returns actool.DefaultTools() minus the named tools (by
// CoreTool.Name()). Used to trim SDK default tools an agent shouldn't have.
func defaultToolsExcept(exclude ...string) []actool.CoreTool {
	drop := make(map[string]bool, len(exclude))
	for _, n := range exclude {
		drop[n] = true
	}
	all := actool.DefaultTools()
	out := make([]actool.CoreTool, 0, len(all))
	for _, t := range all {
		if !drop[t.Name()] {
			out = append(out, wrapConcurrentBash(t))
		}
	}
	return out
}

func (w *Worker) SetCompactionWindowResolver(fn func() int) { w.windowFn = fn }

func (w *Worker) compactionWindow() int {
	if w.windowFn != nil {
		return w.windowFn()
	}
	return w.window
}

// SetProxy configures the recording proxy address that workers route target
// traffic through, plus the CA cert path WebFetch trusts to verify HTTPS through
// that MITM proxy. Empty addr disables the hint.
func (w *Worker) SetProxy(addr, caCert string) { w.proxyAddr, w.proxyCACert = addr, caCert }

// SetTaskProxyResolver installs the per-task proxy resolver: each run asks it
// for the task's own MITM instance; empty result falls back to SetProxy.
func (w *Worker) SetTaskProxyResolver(fn func(taskID int64) (addr, caCert string)) {
	w.taskProxyFn = fn
}

// proxyForTask picks the egress proxy for one run: the task's own MITM instance
// when the resolver binds one; otherwise the global SetProxy value.
func (w *Worker) proxyForTask(taskID int64) (addr, caCert string) {
	if w.taskProxyFn != nil {
		if a, c := w.taskProxyFn(taskID); a != "" {
			return a, c
		}
	}
	return w.proxyAddr, w.proxyCACert
}

// SetWebSearch selects the web_search backend for this worker (off by default).
func (w *Worker) SetWebSearch(o WebSearchOpts) { w.webSearch = o }

// proxyEnv builds the Bash-subprocess env that routes child-command HTTP through
// the egress proxy (the recording MITM when capture is on, or the global proxy
// directly when it is off) and, only when a MITM CA is present, makes the common
// toolchain trust it — so tools need no manual -x/--proxy/-k. Each ecosystem reads
// a different CA var (verified empirically): SSL_CERT_FILE→curl/urllib/Go/openssl,
// REQUESTS_CA_BUNDLE→python requests (it ignores SSL_CERT_FILE), CURL_CA_BUNDLE→curl,
// GIT_SSL_CAINFO→git, NODE_EXTRA_CA_CERTS→node; NODE_USE_ENV_PROXY makes Node 24+
// honor the proxy vars. ALL_PROXY is set too so a socks5 egress proxy (which curl
// only reads from ALL_PROXY, not HTTP(S)_PROXY) works in the capture-off path.
// Empty proxyAddr → nil (direct, unchanged env).
func proxyEnv(proxyAddr, caCert string) []string {
	if proxyAddr == "" {
		return nil
	}
	env := []string{
		"HTTP_PROXY=" + proxyAddr, "HTTPS_PROXY=" + proxyAddr,
		"http_proxy=" + proxyAddr, "https_proxy=" + proxyAddr,
		"ALL_PROXY=" + proxyAddr, "all_proxy=" + proxyAddr, // socks5 egress: curl reads only this
		"NODE_USE_ENV_PROXY=1", // Node 24+: honor HTTP(S)_PROXY in built-in fetch/http
	}
	if caCert != "" {
		env = append(env,
			"SSL_CERT_FILE="+caCert,
			"CURL_CA_BUNDLE="+caCert,
			"REQUESTS_CA_BUNDLE="+caCert,
			"GIT_SSL_CAINFO="+caCert,
			"NODE_EXTRA_CA_CERTS="+caCert,
		)
	}
	return env
}

// uaEnv 在 Bash env 上追加 ARTEX_UA(按任务稳定分配的客户端 UA);
// ua 为空则原样返回,不追加空变量。
func uaEnv(env []string, ua string) []string {
	if ua == "" {
		return env
	}
	return append(env, "ARTEX_UA="+ua)
}

// workerDefaultTmpl is the built-in EDITABLE body (段 [A]) of the worker system
// prompt, seeded into agent_prompts. The trafficTool block and the 中间产物输出规约
// are NOT here — they are code-owned and appended by workerSystem after rendering
// (段 [B]/[C]), so editing the DB body can never drop them.
const workerDefaultTmpl = `你是授权安全测试与红队行动的"执行者"(work agent / 单兵突击手)。你领到【一条意图】(明确的单目标侦察或突破指令)，唯一职责：**打穿本条意图、把高质量情报与实锤结果写回知识图谱、然后立刻收队。**

**红队单兵铁律**：
1. **一单只打一靶，严禁越权自调度**：只执行本条意图锁定的目标与假设。即使提前完成，或从响应头/报错/源码里发现本意图之外的新域名、旁路服务、另一条攻击链线索，**一律通过 insert_assets / record_fact 交回规划者统筹排单，严禁私自拉取未分配目标列表或连续切换新靶开打**。
	2. **边界异味深挖与诚实结论**：初次受阻（WAF 拦截 / 403 / HTTP 500 / 无回显）往往意味触及后端解析或过滤边界——穷尽本方向的编码变形、Content-Type 切换、参数污染与逻辑绕过再输出判断；写事实须如实标注**实测覆盖边界**（如"已测标准 Web 端口"），严禁未扫其他端口就妄断"仅开放某端口"，更严禁凭 HTTP 500 轻率定性为"目标损坏/不可利用"（手段未穷尽或属推断一律标 confidence=inferred）。
3. **边缘感知与授权红线**：严格遵守顶部【操作约束】与脚印红线；先判目标是否位于 CDN/WAF 共享边缘，避免对共享边缘 IP 做无意义全端口扫描。

**高信噪比写回与赏金级实锤门禁（Signal Gate）**：
- **新资产 → insert_assets**：登记子域 / service / endpoint / 指纹 / 认证信息等资产本身；探索结论不写这里。
- **战果线索 → record_fact（传 intent_id）**：将本轮探索归纳为【一条】高信息量增量事实（summary 总结 + detail 展开；确有彼此独立结论才用 facts 数组），写一行简洁 evidence 并标 confidence（observed / inferred）；按需标记 category（negative_result / scope_limit / cleanup_status / evidence）便于跨阶段继承。
- **确认漏洞 → report_finding（传 intent_id 与简明漏洞标题 name）**：**仅限本次亲自触发、具备跨安全边界真实危害（如 RCE、SQLi/SSRF 实锤、跨租户/越权读写、核心凭据/数据泄露等）且拿到可复现请求/响应或命令输出证据时使用**。纯版本号暴露、缺安全头、无凭据 CORS 反射、Self-XSS、未证实接管的悬空解析或仅靠版本推断的疑似 CVE，**严禁调用 report_finding 充数**（有可串联价值的高潜怀疑点用 record_fact 记 inferred 交规划者）。

**专项技能与扩展工具**：
- 遇到前端 SPA/打包 JS 逆向提取隐藏 API 与签名算法、Web 业务热点审计、需真实浏览器交互或外部资产测绘时，先查 Skill 工具列表按需加载对应技能（js-api-recon / tbhm-app-analysis / playwright-cli / tbhm-recon）。
- 涉及双账号/多租户越权（IDOR/BOLA）验证或立足点会话纳管时，按需检索并调用 dual_account_verify、register_session 等扩展工具。

完成本意图后用一句话总结你做了什么、写回了哪些核心结论。

**运行预算**：单次 ` + "`run_seconds`" + `（默认 20 分钟）只是初始预算，**每次 ` + "`report_finding`" + ` 登记实锤漏洞、成功 ` + "`register_session`" + ` 建立立足点会话或落库 ` + "`observed`" + ` 级关键 ` + "`evidence`" + ` 事实都会自动延长预算**——撕开突破口后请放心向纵深打穿。`

// workerIntranetDiscipline 是内网期追加进 worker 正文的短纪律段落(可编辑变体
// "worker.intranet")。只追加,不替换 worker 默认正文,也不覆盖进场预塞。
// 不把 pending_scope 写成出界动作的硬门闩,也不提隧道四件套(本刀不移植)。
const workerIntranetDiscipline = `**内网期纪律**(本任务已有存活立足点会话,处于内网横向阶段):
- **被动优先**:新方向先用 session_recon 只读命令包(网卡/路由/邻居/hosts/监听)拿信息,被动不够再考虑主动探测。
- **新网段进扩展队列**:出当前 task_scope 的 IP 可以已经写入资产图,并按 /24 记入 pending_scope。pending_scope 是官方的 task_scope 扩展队列:人工 approve 后写入 task_scope;它不是对出界动作的硬门闩,不要把资产写回或后续动作卡在「批准之前」。
- **下一跳要挂边或锚**:从已确认的侦察事实开下一跳时,必须经 add_intent 带上 parent_ids(该 fact,形成 derived_from)或对应资产的 asset_ids。既无边也无锚的新意图,进场预塞看不到这些已确认事实。
- **动静控制**:经会话执行的命令注意目标侧日志/进程/网络留痕,避免大批量高噪声动作。`

// workerIntranetRules 是内网期的代码固定尾(不可被 DB 变体正文覆盖)。
const workerIntranetRules = `

**内网红线(不可编辑)**:被动侦察优先;pending_scope 是 task_scope 扩展队列而非出界硬门闩(出界 IP 可能已在资产图中);从已确认侦察事实开下一跳必须挂 derived_from 或对应资产锚,否则进场预塞读不到这些事实;注意动静控制。站在立足点上时，把扫描打回攻击机/平台侧，不要在对方壳里手写扫描器。`

// workerShellCLIRules 是始终追加的代码固定尾(不可被 DB 正文删掉)。不走 DB 变体,
// 不写入 BuiltinPromptSeeds。纪律只指向「Bash 说明里已列出的」,不点名具体 CLI。
const workerShellCLIRules = `

**CLI 优先(不可编辑)**:枚举、爆破、注入、喷洒、指纹，优先用 Bash 说明里已列出的成熟 CLI。工具跑过仍不够，或确是带登录态的业务流、自定义协议，才写短脚本。`

// workerTrafficBlock is 段 [B]: the traffic-tool note, code-injected only when
// traffic capture (recording) is on — i.e. the traffic_* tools actually exist.
// Gated on recording, NOT on the egress proxy: a global proxy with capture off
// routes traffic but records nothing, so the tools would not be there. Not stored,
// not editable.
func workerTrafficBlock(recording bool) string {
	if !recording {
		return ""
	}
	return "\n\n**流量工具**：\n- traffic_search / traffic_get / traffic_blob：回看响应、找已访问过的资源，**先查流量、不要重复 curl 同一 URL**。traffic_search **必须指定 host**、默认只回 3 条极轻量索引(id/method/url/status/resp_len，无响应内容)，需要更多显式调大 limit；可用 body_contains 在请求/响应正文里做全文搜索(至少 3 字符，支持子串和中文，如找密码/密钥/报错/内网地址)；要看某条原文用 traffic_get(id)，其中超大正文显示为 @blob sha256:<hash>，用 traffic_blob(hash) 分段取全文。"
}

// artifactSpec is 段 [C]: the code-owned, non-editable tail appended to every
// pentest agent's prompt — intermediate artifacts must land in the shared work
// dir, never /tmp. Guaranteed present regardless of how the DB body is edited.
// Cross-worker files (SSH keys, route tables, wordlists) go to <task>/shared,
// not the task root: workers do not share a CWD with the planner.
func artifactSpec(dir string) string {
	shared := sharedDirForRun(dir)
	return "\n\n**中间产物输出规约**：脚本、payload、抓到的响应体、临时数据等本角色自己的中间产物，**一律写到工作目录 " + dir + "**（相对路径即写在这里，也可用该绝对路径）——**不要写 /tmp、不要用其它绝对路径**。" +
		"\n**跨单兵共享制品**（SSH 私钥、提取好的 API 路由表、字典、凭据文件等后续意图还要用的文件）只增写入 **" + shared + "**。意图正文和命令里引用这些文件时写该目录下的绝对路径。" +
		"每个 worker 的私有目录是同级的 `i<意图id>/`，任务根目录里没有它们的产物；密钥路径以 shared 目录为准，并要求产出方用 record_fact 的 artifact_paths 记下绝对路径。"
}

// workerArtifactSpec is the worker's 段 [C]: its per-intent run dir is pre-created
// by the engine (ensureRunDir), so it just writes relative paths there — no manual
// mkdir, no cross-worker name collisions. Reusable artifacts go to the sibling
// shared/ directory so the next intent can open them without guessing i*/ paths.
func workerArtifactSpec(runDir string) string {
	shared := sharedDirForRun(runDir)
	return "\n\n**中间产物输出规约**：脚本、payload、抓到的响应体、临时数据等本次意图的私有中间产物，**一律写到本次意图的专属工作目录 " + runDir + "**（已自动建好，直接用相对路径写在这里即可，无需再手动建目录）——**不要写 /tmp、不要用其它绝对路径**。" +
		"\n后续单兵还要用的制品（SSH 私钥、路由表、字典、凭据文件）写到跨单兵共享目录 **" + shared + "**（只增不删），并在 record_fact 的 artifact_paths 里记下这些绝对路径。共享文件只放这个目录。"
}

// sharedDirForRun returns <taskDir>/shared for either the task root
// (.../tasks/<id>, planner and main agent) or an intent run dir
// (.../tasks/<id>/i<intentID>, worker).
func sharedDirForRun(dir string) string {
	base := filepath.Base(dir)
	if len(base) > 1 && base[0] == 'i' {
		if _, err := strconv.ParseInt(base[1:], 10, 64); err == nil {
			dir = filepath.Dir(dir)
		}
	}
	return filepath.Join(dir, "shared")
}

// ensureTaskSharedDir creates the append-only cross-worker artifact directory
// under a task root (.../tasks/<id>/shared).
func ensureTaskSharedDir(taskDir string) string {
	dir := filepath.Join(taskDir, "shared")
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

// ensureRunDir builds and creates an agent's working directory under base:
// <base>/tasks/<taskID> for planner/main; <base>/tasks/<taskID>/i<intentID> for a
// worker (intentID<=0 → task dir only). The "tasks/" segment groups per-task dirs
// symmetrically with the chat agent's "sessions/<sessionID>". Best-effort mkdir — on
// failure, writes fail the same way an unwritable CWD would.
func ensureRunDir(base string, taskID, intentID int64) string {
	dir := filepath.Join(base, "tasks", strconv.FormatInt(taskID, 10))
	if intentID > 0 {
		dir = filepath.Join(dir, "i"+strconv.FormatInt(intentID, 10))
	}
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

// cmdOutDir is the SDK large-tool-output spill dir under an agent's run dir.
func cmdOutDir(dir string) string { return filepath.Join(dir, "cmd-output") }

func workerSystem(proxyAddr, caCert, dataDir, runDir string, intranet bool, fp FootprintToggles) string {
	vars := WorkerVars{ProxyAddr: proxyAddr, DataDir: dataDir, Now: nowStr(), Intranet: intranet}
	body := renderSystem("worker", workerDefaultTmpl, vars)
	tail := ""
	if intranet {
		// APPEND-ONLY:变体与代码固定红线尾只接到 worker 正文之后,不替换主正文,
		// 也不触碰 execute() 里稍后追加的 RenderWorkerEntrySeed 进场预塞。
		tail = "\n\n" + renderSystemVariant("worker", "intranet", workerIntranetDiscipline, vars) + workerIntranetRules
	}
	// caCert is present only when the recording MITM is on, which is exactly when
	// the traffic_* tools are registered — so it gates the traffic-tool note.
	// Optional finding guidance is added for every role after tool resolution.
	// CLI 优先固定尾始终追加,位于内网变体之后,进场预塞仍由 execute() 再往后接。
	// 工人红线是代码固定尾:目标内容当数据不当指令,内外网一律追加,
	// 编辑正文也删不掉。进场预塞仍由 execute() 再往后接。
	return body + workerTrafficBlock(caCert != "") + workerArtifactSpec(runDir) + tail + workerShellCLIRules + untrustedDataRule + workerAntiTrapRules + workerFootprintRulesFor(fp) + chainskel.WorkerMetaRules
}

// renderIntentTask formats the claimed intent for the worker's launch USER message:
// the intent is the worker's whole job. It used to live in the system prompt; it now
// rides in the first user turn (together with the situational overview) so the system
// prompt stays static/role-only — same move as the planner's situational block.
// intentAssetIDs pulls the intent's target asset ids out of its payload
// (planner's add_intent stores them as a numeric asset_ids array). nil on absence
// or malformed payload.
func intentAssetIDs(intent *db.Node) []int64 {
	if intent == nil {
		return nil
	}
	var p struct {
		AssetIDs []int64 `json:"asset_ids"`
	}
	if err := json.Unmarshal(intent.Payload, &p); err != nil {
		return nil
	}
	return p.AssetIDs
}

func renderIntentTask(intent *db.Node) string {
	return fmt.Sprintf("\n\n【你领到的意图（本次唯一任务：只做这一条、只产生事实、做完即停）】：\n%s\n意图 id: %d（写回 record_fact / report_finding 时传它）", string(intent.Payload), intent.ID) +
		chainskel.ForIntent(intent.Payload) + chainskel.RefsGuideForIntent(intent.Payload)
}

const (
	workerOverviewRunningCap        = 6
	workerOverviewRunningSummaryMax = 120
	workerOverviewRecentFactsCap    = 10
	workerOverviewFindingsCap       = 6
	workerOverviewColdDigestsCap    = 3
	workerOverviewColdDigestBodyMax = 300
	workerOverviewHintsCap          = 8
	workerOverviewHintTextMax       = 200
	workerOverviewRelatedListCap    = 5
)

// renderWorkerGraphOverview folds a slimmed global situational snapshot into the
// worker's launch USER message for AWARENESS ONLY. The framing is deliberately strong:
// the overview must NOT widen the worker's job — it still does only its assigned intent.
// Planner-only fields (open_intents, recent_done_intents, crown_jewels, goals, coverage)
// are dropped and remaining lists are tightly bounded so overview does not dominate
// per-turn worker input tokens. Full graph data remains one tool call away.
func renderWorkerGraphOverview(data map[string]any, seedFactIDs map[int64]bool) string {
	// 规划者专用调度字段（coverage/open_intents/recent_done_intents/crown_jewels/goals/
	// cold_digests_more）与 worker「只做领到的那条意图」的职责无关且体积占比最大 →
	// 从 worker 视图里剔除。data 是本次 worker 专属的新 map，改它不影响 planner。
	for _, k := range []string{
		"coverage", "open_intents", "recent_done_intents",
		"crown_jewels", "goals", "cold_digests_more",
		"task_assets", "task_assets_total",
	} {
		delete(data, k)
	}
	// running_intents：worker 只需粗略知道其他在跑意图的标题以防撞车，保留前 N 条短摘要。
	if ri, ok := data["running_intents"].([]map[string]any); ok {
		lim := min(len(ri), workerOverviewRunningCap)
		slim := make([]map[string]any, 0, lim)
		for _, m := range ri[:lim] {
			entry := map[string]any{"id": m["id"]}
			if s, ok := m["summary"].(string); ok {
				entry["summary"] = clipPlainRunes(s, workerOverviewRunningSummaryMax)
			}
			slim = append(slim, entry)
		}
		data["running_intents"] = slim
	}
	// 阶段三去重 + 体积封顶：进场预塞(system prompt)已按本意图带上相关已确认事实。
	// 概览里的 recent_facts 剔除重复后只保留最新一小窗（≤10 条，摘要封顶 160 字）。
	if rf, ok := data["recent_facts"].([]map[string]any); ok && len(rf) > 0 {
		kept := make([]map[string]any, 0, min(len(rf), workerOverviewRecentFactsCap))
		for _, m := range rf {
			if len(seedFactIDs) > 0 {
				if id, ok := m["id"].(int64); ok && seedFactIDs[id] {
					continue // 已在进场预塞里，省去重复
				}
			}
			if s, ok := m["summary"].(string); ok {
				m["summary"] = clipPlainRunes(s, factSummaryMax)
			}
			kept = append(kept, m)
			if len(kept) >= workerOverviewRecentFactsCap {
				break
			}
		}
		data["recent_facts"] = kept
	}
	// finding_list 封顶并裁短摘要，防止多条超长漏洞摘要撑爆概览（全量走 list_findings）。
	if fl, ok := data["finding_list"].([]map[string]any); ok {
		lim := min(len(fl), workerOverviewFindingsCap)
		slim := make([]map[string]any, 0, lim)
		for _, m := range fl[:lim] {
			entry := map[string]any{"id": m["id"]}
			if from, exists := m["from_intent"]; exists {
				entry["from_intent"] = from
			}
			if s, ok := m["summary"].(string); ok {
				entry["summary"] = clipPlainRunes(s, workerOverviewRunningSummaryMax)
			}
			slim = append(slim, entry)
		}
		data["finding_list"] = slim
	}
	// cold_digests：worker 不需携带多达 15 篇完整冷区长摘要；仅保留最新 3 篇且正文裁至 300 字，
	// 需要回查冷区历史时可按 id 调 expand_digest 或 list_facts。
	if cds, ok := data["cold_digests"].([]map[string]any); ok && len(cds) > 0 {
		lim := min(len(cds), workerOverviewColdDigestsCap)
		slim := make([]map[string]any, 0, lim)
		for _, cd := range cds[:lim] {
			entry := map[string]any{"id": cd["id"]}
			if mc, ok := cd["member_count"]; ok {
				entry["member_count"] = mc
			}
			if body, ok := cd["body"].(string); ok {
				entry["body"] = clipPlainRunes(body, workerOverviewColdDigestBodyMax)
			}
			slim = append(slim, entry)
		}
		data["cold_digests"] = slim
	}
	// hints：保留最新 8 条、每条正文封顶 200 字。
	if hs, ok := data["hints"].([]map[string]any); ok && len(hs) > 0 {
		lim := min(len(hs), workerOverviewHintsCap)
		slim := make([]map[string]any, 0, lim)
		for _, h := range hs[:lim] {
			entry := map[string]any{"id": h["id"], "state": h["state"]}
			if text, ok := h["text"].(string); ok {
				entry["text"] = clipPlainRunes(text, workerOverviewHintTextMax)
			}
			if refs, ok := h["traffic_refs"]; ok {
				entry["traffic_refs"] = refs
			}
			slim = append(slim, entry)
		}
		data["hints"] = slim
	}
	// related_tasks：跨任务概览在 planner 上限 48k runes，对 worker 裁剪为轻量索引
	// （保留任务信息、计数和少量近期 findings/facts 摘要，细节走 list_facts/list_findings）。
	if rts, ok := data["related_tasks"].([]map[string]any); ok && len(rts) > 0 {
		slim := make([]map[string]any, 0, len(rts))
		for _, rt := range rts {
			entry := map[string]any{}
			for _, k := range []string{"source_task_id", "inherited", "task", "facts", "findings"} {
				if v, exists := rt[k]; exists {
					entry[k] = v
				}
			}
			for _, listKey := range []string{"recent_findings", "recent_facts"} {
				if list, ok := rt[listKey].([]map[string]any); ok && len(list) > 0 {
					lim := min(len(list), workerOverviewRelatedListCap)
					sub := make([]map[string]any, 0, lim)
					for _, item := range list[:lim] {
						cp := map[string]any{"id": item["id"]}
						if s, ok := item["summary"].(string); ok {
							cp["summary"] = clipPlainRunes(s, factSummaryMax)
						}
						sub = append(sub, cp)
					}
					entry[listKey] = sub
				}
			}
			slim = append(slim, entry)
		}
		data["related_tasks"] = slim
	}
	b, err := json.Marshal(data)
	if err != nil {
		return "" // fall back silently: the worker just won't have the global context
	}
	return "\n\n【全局探索态势（只读，帮你把自己这条意图放进大局看）】：\n" +
		"下面是整个任务当前的精简探索概况（需要完整历史可按需调 list_facts / list_findings / node_detail）。用途有两个：一是知道别人已发现什么，别重复；二是让你探自己这条意图时，能联想到它和全局的关系。\n" +
		"**发散是好事**：探本意图时尽管深想、多联想。唯一的界线是——别真的动手去执行别的意图（那是别的 worker 的事，由规划者调度）。但凡你联想到有价值的线索（跨资产的联动、疑似另一条利用链的入口、全局层面的可疑点），**务必写进 fact 交规划者**——这是你重要的产出，不是可有可无。宁可多报一条让规划者判断，也别自己咽下去。\n" +
		string(b)
}

// Execute runs one intent. hooks (the per-task Guard) gates every tool call; may
// be nil. emit, if non-nil, receives one ActivityRecord per execution step.
// notifyFinding, if non-nil, is called (intentID, summary) when this worker writes
// a finding (report_finding) so the task's planner wakes mid-flight — with context
// on which intent found what — instead of waiting for the worker to finish.
// Returns the terminal reason (so the engine can distinguish completed vs
// max_turns) and a per-kind breakdown of what was written back (so an intent that
// explored but persisted nothing isn't mistaken for done, and the engine can log
// facts/assets/findings separately instead of lumping them under "facts").
func (w *Worker) Execute(ctx context.Context, name string, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, intent *db.Node, hooks harness.HookRunner, emit func(db.Activity), enr EnrichTrigger, notifyFinding func(int64, string)) (harness.TerminalReason, WriteCounts, error) {
	return w.execute(ctx, name, taskID, as, ts, intent, hooks, emit, enr, notifyFinding, "", "")
}

// ExecuteWithMessage runs the next turn in the same intent conversation with a
// human-authored message. The HTTP handler does not edit the transcript;
// agentcore records the message as a normal user turn when this Worker starts.
// This keeps Worker continuation identical to the regular agent chat flow.
// SanitizeSessionForWAF scrubs recent sensitive tool_use/tool_result blocks at the
// tail of the worker's transcript after an upstream LLM gateway HTTP 403 WAF block.
func (w *Worker) SanitizeSessionForWAF(explorationID, intentID int64) (bool, error) {
	if w == nil || w.tx == nil || explorationID <= 0 || intentID <= 0 {
		return false, nil
	}
	return SanitizeTranscriptTailForWAF(w.tx, WorkerSessionID(explorationID, intentID))
}

func (w *Worker) ExecuteWithMessage(ctx context.Context, name string, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, intent *db.Node, hooks harness.HookRunner, emit func(db.Activity), enr EnrichTrigger, notifyFinding func(int64, string), requestID, message string) (harness.TerminalReason, WriteCounts, error) {
	return w.execute(ctx, name, taskID, as, ts, intent, hooks, emit, enr, notifyFinding, strings.TrimSpace(requestID), strings.TrimSpace(message))
}

func (w *Worker) execute(ctx context.Context, name string, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, intent *db.Node, hooks harness.HookRunner, emit func(db.Activity), enr EnrichTrigger, notifyFinding func(int64, string), requestID, message string) (harness.TerminalReason, WriteCounts, error) {
	tsx := NewToolSet(ts, name)
	tsx.SetFindingRecorder(w.findingRecorder)
	tsx.SetTaskID(taskID)
	coverageEnabled := as == nil || as.CoverageEnabled(taskID)
	tsx.SetCoverageEnabled(coverageEnabled)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetOwnerNode(intent.ID) // assets this worker discovers anchor to its intent → visible to the task
	tsx.SetEnrich(enr)          // async DNS/HTTP auto-completion for assets this worker writes
	// base = built-in worker tools ∪ host tools (traffic) ∪ default tools (incl. Bash);
	// then augment with the agent's visible skills/MCP. During the SDK settlement
	// phase, Bash is hidden via Settlement.DisabledTools (no local gating needed).
	base := append(tsx.WorkerTools(), w.extraTools...)
	// worker 刻意不给 MultiEdit/Glob/Grep：文件精改用 Edit、检索走 Bash(grep/find)，
	// 收敛工具面、减少低价值调用。其余 SDK 默认工具(Read/Write/Edit/LS/Bash/Sleep)照常。
	base = append(base, defaultToolsExcept("MultiEdit", "Glob", "Grep")...)
	ctx = WithRunInfo(ctx, RunInfo{TaskID: taskID, ExplorationID: explorationID(ts), IntentID: intent.ID})
	tools, def, cleanup := AugmentTools(ctx, "worker", base)
	defer cleanup()

	// 意图是 worker 的【唯一职责、贯穿整个 run 的不变量】→ 连同启动指令、意图锚定的目标资产
	// 原始数据一起放进 system prompt：system 每次 run 都重新拼一遍、绝不会被 compaction 压掉，
	// 长 run 里意图永远在场，续跑时也不依赖 transcript 历史是否留住那条首消息。代价是 system
	// 混入 per-intent 易变数据、失去跨意图缓存复用；这是刻意的取舍（意图丢失比省 token 严重得多）。
	// 与 planner「态势块放 user turn」分叉是有意的：planner 本身是产意图的那个、没有单一 mandate，
	// worker 有。仅【全局态势 overview】留在启动 user 消息里——它可降级、容忍 stale，压掉无碍。
	// 本次意图的专属工作目录 <workDir>/tasks/<taskID>/i<intentID>，引擎侧先建好。
	// 跨单兵制品在同级 shared/，与规划者约定的密钥/字典路径对齐。
	runDir := ensureRunDir(w.workDir, taskID, intent.ID)
	ensureTaskSharedDir(filepath.Dir(runDir))
	// The run-wide intent is not the current tool action. Do not forward it or
	// inherit a parent run's background into the action reviewer.
	ctx = intercept.WithReviewContext(ctx, runDir, intercept.ReviewBackground{})
	snap := newGraphSnapshot(ts) // overview + entry seed share one graph read
	// 进场预塞先算(只读)：worker 的全局态势 overview 用它已带的事实 id 集合去重，
	// 不把 seed 已含的相关事实在概览里再下发一遍(阶段三：减少每轮重复发送)。
	entrySeed := loadWorkerEntrySeedFrom(ts, snap, as, intent)
	overview := renderWorkerGraphOverview(tsx.graphOverviewDataFrom(snap), entrySeedFactIDSet(entrySeed))
	proxyAddr, proxyCA := w.proxyForTask(taskID)
	sysBody := workerSystem(proxyAddr, proxyCA, w.workDir, runDir, w.intranetForTask(taskID), w.footprintForTask(taskID))
	if w.wantConstraints() {
		sysBody += constraintBlock(ts) // 操作约束(若有)注入系统提示,worker 执行时严格遵守
	}
	sysBody += honeypotBlock(tsx, as, intent.ID) // 无蜜罐资产时为空串,不改变提示词
	// 意图块 → 意图锚定资产块 → 启动指令，依次追加到 system 尾部（与 constraintBlock 同一套追加法）。
	sysBody += renderIntentTask(intent)
	if as != nil {
		if ids := intentAssetIDs(intent); len(ids) > 0 {
			if assets, err := as.GetByIDs(ids); err == nil && len(assets) > 0 {
				if b, err := json.Marshal(assets); err == nil {
					sysBody += "\n\n本意图 asset_ids 对应的目标资产：\n" + WrapUntrustedData("target-assets", string(b))
				}
				// 意图明确针对的这些资产 → 自动纳入任务测试范围（与 insertAssets 同一套
				// 保守粒度）。upsertTaskScope 的 ON CONFLICT DO NOTHING + uq_task_scope
				// 唯一索引保证不会重复添加；重跑/重试同样是幂等 no-op。
				// 资产覆盖度功能关闭时不再累积测试范围(分母)。
				if coverageEnabled {
					for _, a := range assets {
						_ = as.AddAutoScope(taskID, a.Type, a.Domain, a.URL, a.IP)
					}
				}
			}
		}
	}
	// 进场预塞：与本意图相关的已确认事实 + 已确认可达但未兑现的下一跳。
	// 压缩/预取失败只打「图谱不完整」标记，fail-soft，不阻断进场、不写目标失败。
	seedBlock := RenderWorkerEntrySeed(entrySeed)
	sysBody += seedBlock
	sysBody += w.credentialSeedBlock(ctx, taskID) // 无继承凭据或查询失败时为空串
	sysBody += "\n\n开始执行上面这条意图：只做它、只产生事实、assets、finding、做完即停。"
	log.Printf("[worker] intent #%d prompt chars: system=%d overview=%d entry_seed=%d",
		intent.ID, utf8.RuneCountInString(sysBody), utf8.RuneCountInString(overview), utf8.RuneCountInString(seedBlock))
	system, boundary := deferredSystem(sysBody, def)
	// 任务级 deadline(经 ctx 注入)夹逼本 run 的墙钟预算 + 决定收尾词(见 taskclock.go)。
	tc := taskClockFrom(ctx)
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, w.runTimeout)
	reserve := 120 * time.Second
	if w.settleTimeout != nil {
		reserve = *w.settleTimeout
	}
	ctx, workDuration := withRunBudget(ctx, time.Now(), maxDur, reserve)
	maxOptsDuration := workDuration
	notifyFindingWrapped := notifyFinding
	if maxDur >= 10*time.Minute && !clamped && workDuration > 0 {
		ctx = enableRunBudgetExtension(ctx, maxDur)
		maxOptsDuration = workDuration + maxDur
		notifyFindingWrapped = func(iid int64, summary string) {
			if added, total := extendRunBudgetFromContext(ctx, 10*time.Minute); added > 0 {
				log.Printf("[worker %s] intent #%d 发现漏洞里程碑，运行预算续期 +%s（累计 +%s）", name, iid, added, total)
			}
			if notifyFinding != nil {
				notifyFinding(iid, summary)
			}
		}
	}
	tsx.SetNotifyFinding(notifyFindingWrapped) // report_finding 落库时当场唤醒 planner + 里程碑续期
	settle := wrapupSettlement("worker", []string{"Bash"})
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("worker", []string{"Bash"}, clamped)
	}
	window := w.compactionWindow()
	budgetProvider := &runBudgetProvider{inner: w.prov}
	opts := agentcore.Options{
		Provider:        budgetProvider,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		// WebFetch 走记录代理，其 HTTP 与 curl 一样被留痕；载入代理 CA 让经 MITM
		// 重签的 HTTPS 证书能【正常校验通过】（而非关掉校验）。proxy 空则直连。
		EnableWebFetch: true,
		WebFetchProxy:  proxyAddr,
		WebFetchCACert: proxyCA,
		// 联网搜索(可选)。ddgs 无需 key；brave-free 需 BraveKey；tavily 需 TavilyKey。
		// WebSearchProxy 是独立的出口代理(http/https/socks5)，与记录流量的 MITM 代理无关；空则直连。
		EnableWebSearch:       w.webSearch.Enabled,
		WebSearchBackend:      w.webSearch.Backend,
		BraveSearchAPIKey:     w.webSearch.BraveKey,
		TavilySearchAPIKey:    w.webSearch.TavilyKey,
		DeepSeekSearchBaseURL: w.webSearch.DeepSeekBaseURL,
		DeepSeekSearchAPIKey:  w.webSearch.DeepSeekAPIKey,
		DeepSeekSearchModel:   w.webSearch.DeepSeekModel,
		WebSearchProxy:        w.webSearch.Proxy,
		// Bash 子命令的 HTTP 默认走记录代理 + 信任其 CA（工具无需 -x/-k）。
		BashEnv:    shellEnv(w.workDir, uaEnv(proxyEnv(proxyAddr, proxyCA), w.uaForTask(taskID))),
		WorkingDir: runDir,
		MaxTurns:   w.maxTurns, // 0 = unlimited (configurable in agent management)
		// 墙钟预算,轮边界判,不打断半路;0 = 不限。有任务级 deadline 时夹逼到 min(自身预算,
		// 距 deadline 剩余),让本 run 在任务到点时自然进收尾(见 taskclock.go)。
		MaxDuration: maxOptsDuration,
		// 命中预算(轮次 OR 时长)→ SDK 跑一轮收尾(隐藏 Bash),把已识别的写回,避免烂尾。
		// clamped(被任务 deadline 夹逼)时用 PromptByReason:因超时=任务到点→任务超时词,
		// 因步数=夹逼窗口内步数先耗尽→回落 per-run 词。非 clamped 维持纯 per-run。
		Settlement: settle,
		// ARTEX spills large output to cmd-output/ with bounded head+tail previews.
		ToolOutputDir: cmdOutDir(runDir),
		Compaction:    compactionConfig(window), // long tool-heavy runs stay within the window
		Todos:         actool.NewTodoStore(),    // 会话级临时待办（TodoWrite），纯规划用，退出即丢
		NonStreaming:  w.nonStreaming(),         // 该 profile 选非流式时走 Provider.Complete
		MaxTokens:     w.maxTokens(),            // 0 = 不发上限,由服务端默认值决定
	}
	AttachStableWebFetch(&opts, w.uaForTask(taskID)) // 官方 WebFetch 请求头用本任务稳定 UA，回包走 untrusted-data
	if hooks != nil {                                // typed-nil guard: only set when concrete (avoids harness panic)
		AttachStopLossWrites(hooks, func() (WriteCounts, bool) { return tsx.Writes(), true })
		opts.Hooks = hooks
		if h, ok := hooks.(stopLossHooks); ok {
			budgetProvider.loss = h.mon
		}
	}
	if w.tx != nil { // persist raw LLM conversation; one file per worked intent
		opts.Transcript = w.tx
		opts.SessionID = WorkerSessionID(ts.ID(), intent.ID)
	}
	intentID := intent.ID
	emitWrap := func(r db.Activity) {
		if emit != nil {
			r.NodeID, r.Worker = &intentID, name
			emit(r)
		}
	}
	// 意图 / 启动指令 / 意图锚定资产已随 system prompt 下发（见上方 sysBody 组装）。
	// 这条启动 user 消息只承载【全局态势 overview】——可降级的了解大局信息，压掉无碍。
	// overview 罕见地 marshal 失败为空时，回退一句启动词，避免首轮出现空 user 消息。
	input := overview
	if strings.TrimSpace(input) == "" {
		input = "开始执行 system 里领到的意图：只做它、只产生事实、assets、finding、做完即停。"
	}

	// 实验功能:开启后由 noa 接管上下文压缩(归档集中在 <workDir>/noa/<SessionID> 下,持久)。
	noaSession := WorkerSessionID(ts.ID(), intent.ID)
	installRuntimeCompactor(&opts, ts)
	enableNoa(&opts, w.noaEnabledFn, w.workDir, noaSession, window, noaWarn(noaSession))
	attachToolOutputSpilling(&opts)
	ctx = attachSideCapture(ctx, &opts)
	s := agentcore.NewSession(opts)
	defer s.Close() // release the session's background-task manager (temp dir + processes)

	// Resume prior conversation if this intent was paused/blocked/exhausted and is
	// being re-run. The transcript ID is deterministic per intent, so if a prior
	// session exists the worker continues from where it left off instead of
	// restarting from scratch.
	alreadyRecorded := false
	var resumeWarning string
	if w.tx != nil {
		resumeWarning = resumeHistory(s, opts.SessionID, name, emitWrap)
		if resumeWarning != "" {
			text := fmt.Sprintf("Worker %s, intent #%d, session %s: %s", name, intent.ID, opts.SessionID, strings.TrimSpace(resumeWarning))
			if _, err := ts.AddNode(db.KindHint, map[string]any{"text": text}, 0, "active", name, nil); err != nil {
				log.Printf("[resume] session=%s intent=%d: planner hint failed: %v", opts.SessionID, intent.ID, err)
				emitWrap(db.Activity{Kind: "error", IsError: true, Summary: "history restoration warning could not be saved for planner", Detail: err.Error()})
			}
		}
		alreadyRecorded = requestID != "" && hasWorkerChatMessage(s.Messages(), requestID)
		if len(s.Messages()) > 0 && message == "" {
			seedUnlockFromHistory(s.Messages(), def.UnlockSkill)
			input = "继续执行。"
		} else if len(s.Messages()) > 0 {
			seedUnlockFromHistory(s.Messages(), def.UnlockSkill)
		}
	}
	if message != "" {
		if alreadyRecorded {
			input = "继续执行上一次人工对话输入的新意图。不要重复已经完成的动作。"
		} else if len(s.Messages()) > 0 {
			input = workerChatMarker(requestID) + "\n【人工对话输入的新意图】\n" + message +
				"\n\n请立即按这条人工输入执行，完成后再根据上下文决定原任务是否需要继续。"
		} else {
			input += "\n\n" + workerChatMarker(requestID) + "\n【人工对话输入的新意图】\n" + message +
				"\n\n请优先执行这条人工输入。"
		}
	}

	reason, err := captureWorkerSession(ctx, s, resumeWarning+input, emitWrap)
	if !budgetProvider.loss.Fired() {
		w.recoverSettlement(ctx, s, opts, settle, err, tsx, emitWrap)
	}
	return reason, tsx.finishEvidenceWrites(), err
}

func captureWorkerSession(ctx context.Context, s *agentcore.Session, input string, emit func(db.Activity)) (harness.TerminalReason, error) {
	runCtx := ctx
	var hardEnd *RunBudgetError
	if b, ok := ctx.Value(runBudgetKey{}).(runBudget); ok {
		hardEnd = &RunBudgetError{Deadline: b.maxHardDeadline()}
		var cancel context.CancelFunc
		runCtx, cancel = context.WithDeadlineCause(ctx, b.maxHardDeadline(), hardEnd)
		defer cancel()
	}
	_, reason, err := captureRunSession(runCtx, s, input, emit)
	if hardEnd != nil && context.Cause(runCtx) == hardEnd && errors.Is(err, context.DeadlineExceeded) {
		return harness.ReasonTimeout, hardEnd
	}
	if isRunBudgetError(err) {
		return harness.ReasonTimeout, err
	}
	return reason, err
}
