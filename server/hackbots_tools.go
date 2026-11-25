// hackbots_tools.go 播种 Hackbots Toolkit 的可执行工具（tools 表 system=false）。
//
// 这些工具只是"脚本的可调用外壳"：命令模板里用 {{ARTEX_PYTHON}} / {{ARTEX_NODE}}
// / {{ARTEX_SKILL_DIR}} 指向仓库 skills/ 下随包分发的脚本，运行时不依赖任何外部
// agent（Codex / Claude）。脚本本身零第三方依赖（Python 标准库 + Node 内置模块）。
//
// 播种用 ON CONFLICT DO NOTHING：用户在页面上改过描述/绑定或禁用后，重启不会被
// 覆盖。要长期关掉某个工具就禁用，不要删（删了下次启动会补回来）。
package server

import (
	"encoding/json"
	"log"
	"os/exec"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// hackbotsTool 是一条工具播种定义。schema/command 用 JSON 文本，便于直接入库。
type hackbotsTool struct {
	Key     string
	Desc    string
	Schema  string
	Command string
	Agents  []string
}

// hackbotsTools 是随包分发的工具清单。绑定只给真正会用到它们的 agent：
// 侦察链（worker/pentest/auto）拿 JS 分析工具，Caido 侧工具只给 pentest/auto
// （worker 跑在任务里，通常不直接连本地代理）。
func hackbotsTools() []hackbotsTool {
	recon := []string{"worker", "mainagent", "pentest", "auto"}
	caido := []string{"pentest", "auto"}
	return []hackbotsTool{
		{
			Key:     "js_extract_endpoints",
			Desc:    "从本地 JS 文件或目录里提取 API 端点、路径与 URL（正则去重，扫描 .js 与源码目录）。先把目标 JS 抓到任务工作目录再用它；需要 AST 级路由分类时改用 jshero_extract。完整流程见技能 js-api-recon。",
			Schema:  `{"type":"object","properties":{"path":{"type":"string","description":"本地文件或目录的绝对路径（目录会递归扫描）"}},"required":["path"]}`,
			Command: `{{ARTEX_PYTHON}} {{ARTEX_SKILL_DIR}}/js-api-recon/scripts/regex/extract_endpoints.py {path}`,
			Agents:  recon,
		},
		{
			Key:     "js_lazy_chunks",
			Desc:    "从本地已下载的 webpack/Vite bundle 里重建懒加载 chunk 文件名并下载到指定目录（补齐首屏没加载的代码）。dry_run=true 只列出发现的 chunk 与解析后的 URL，不下载；建议先 dry_run 确认 publicPath 再正式下载。完整流程见技能 js-api-recon。",
			Schema:  `{"type":"object","properties":{"base_url":{"type":"string","description":"目标站点根 URL，用于解析相对 chunk 路径，例如 https://example.com/"},"dir":{"type":"string","description":"存放已下载 bundle 并接收 chunk 的本地目录（绝对路径）"},"dry_run":{"type":"boolean","default":false,"description":"true 时只列出 chunk 不下载"}},"required":["base_url","dir"]}`,
			Command: `{{ARTEX_NODE}} {{ARTEX_SKILL_DIR}}/js-api-recon/scripts/chunks/fetch_lazy_chunks.js {base_url} --dir {dir}{{IF dry_run}} --dry-run{{END}}`,
			Agents:  recon,
		},
		{
			Key:     "jshero_discover_chunks",
			Desc:    "JShero 静态阶段：从已收集的 JS 里嗅探未触发的 webpack chunk 映射并写 chunk-urls.txt（jxscout 对标）。run_root 是本次运行目录（内含 raw-js/ inline-js/ historical-js/）。完整流程见技能 js-api-recon。",
			Schema:  `{"type":"object","properties":{"run_root":{"type":"string","description":"本次运行的根目录（绝对路径），需含 raw-js/ 等子目录"},"domain":{"type":"string","description":"可注册域名，用于范围过滤与台账定位"},"brute":{"type":"integer","default":0,"description":"文件名无哈希时按序号暴力枚举的上限，0=关闭"}},"required":["run_root","domain"]}`,
			Command: `{{ARTEX_PYTHON}} {{ARTEX_SKILL_DIR}}/js-api-recon/scripts/jshero/discover_chunks.py --run-root {run_root} --domain {domain} --brute {brute}`,
			Agents:  recon,
		},
		{
			Key:     "jshero_scan_findings",
			Desc:    "JShero 分析阶段：用随包 secrets_patterns.json（约 1600 条规则）扫描已收集 JS 的敏感凭据，并检测 DOM XSS 的危险 source→sink 汇聚点，结果按台账去重。完整流程见技能 js-api-recon。",
			Schema:  `{"type":"object","properties":{"run_root":{"type":"string","description":"本次运行的根目录（绝对路径）"},"domain":{"type":"string","description":"可注册域名，用于台账定位"}},"required":["run_root","domain"]}`,
			Command: `{{ARTEX_PYTHON}} {{ARTEX_SKILL_DIR}}/js-api-recon/scripts/jshero/scan_findings.py --run-root {run_root} --domain {domain}`,
			Agents:  recon,
		},
		{
			Key:     "jshero_merge_runs",
			Desc:    "JShero 合并阶段：把多轮独立收集（runset 下的多个 pass）按 SHA-256 去重合并成一份，输出收敛率。完整流程见技能 js-api-recon。",
			Schema:  `{"type":"object","properties":{"runset_root":{"type":"string","description":"包含多个 pass 子目录的 runset 根目录（绝对路径）"}},"required":["runset_root"]}`,
			Command: `{{ARTEX_PYTHON}} {{ARTEX_SKILL_DIR}}/js-api-recon/scripts/jshero/merge_runs.py --runset-root {runset_root}`,
			Agents:  recon,
		},
		{
			Key:     "jshero_build_report",
			Desc:    "JShero 报告阶段：把一次运行目录里的端点/参数/凭据/汇聚点结果渲染成 HTML 与 Markdown 报告。完整流程见技能 js-api-recon。",
			Schema:  `{"type":"object","properties":{"run_root":{"type":"string","description":"本次运行的根目录（绝对路径）"},"domain":{"type":"string","description":"可注册域名"}},"required":["run_root","domain"]}`,
			Command: `{{ARTEX_PYTHON}} {{ARTEX_SKILL_DIR}}/js-api-recon/scripts/jshero/build_report.py --run-root {run_root} --domain {domain}`,
			Agents:  recon,
		},
		{
			Key:     "jshero_extract",
			Desc:    "JShero 增强提取器：按完整/绝对/相对（带斜杠）/相对（无斜杠）四类对链接分类，产出端点、参数与方法并同步 per-target 台账（只报新增面）。seed 用于解析相对链接。完整流程见技能 js-api-recon。",
			Schema:  `{"type":"object","properties":{"run_root":{"type":"string","description":"本次运行的根目录（绝对路径）"},"domain":{"type":"string","description":"可注册域名"},"seed":{"type":"string","description":"解析相对链接用的种子 URL，缺省 https://<domain>"}},"required":["run_root","domain"]}`,
			Command: `{{ARTEX_PYTHON}} {{ARTEX_SKILL_DIR}}/js-api-recon/scripts/jshero/extract_endpoints.py --run-root {run_root} --domain {domain}{{IF seed}} --seed {seed}{{END}}`,
			Agents:  recon,
		},
		{
			Key:     "http_fingerprint_probe_plan",
			Desc:    "生成 HTTP 指纹主动探测计划（banner GET、随机 404、默认文件 HEAD/GET、两个畸形请求解析器检查），只输出计划不发起请求。需要主动授权时再逐条执行，并把命中写回事实。完整流程见技能 js-api-recon。",
			Schema:  `{"type":"object","properties":{"target":{"type":"string","description":"目标 URL 或主机名"}},"required":["target"]}`,
			Command: `{{ARTEX_PYTHON}} {{ARTEX_SKILL_DIR}}/js-api-recon/scripts/caido/plan_http_fingerprint_probes.py {target}`,
			Agents:  caido,
		},
		{
			Key:     "caido_collect_api_traffic",
			Desc:    "从本地 Caido（默认 127.0.0.1:8080）GraphQL 拉取目标及其相关子域的流量并做 API 指纹聚类。需要 Caido 正在运行且已抓到该目标；未运行或没流量时如实返回 blocked/no-data，不要臆造指纹。cli 路径取 $CAIDO_GRAPHQL_BIN 或 PATH。完整流程见技能 js-api-recon。",
			Schema:  `{"type":"object","properties":{"target":{"type":"string","description":"目标 URL 或主机名"},"limit":{"type":"integer","default":300,"description":"最多拉取的记录数"},"host_mode":{"type":"string","enum":["related-domain","exact-host"],"description":"默认 related-domain（含相关子域）；exact-host 只看字面主机"}},"required":["target"]}`,
			Command: `{{ARTEX_PYTHON}} {{ARTEX_SKILL_DIR}}/js-api-recon/scripts/caido/collect_caido_api_traffic.py {target} --limit {limit}{{IF host_mode}} --host-mode {host_mode}{{END}}`,
			Agents:  caido,
		},
	}
}

// HackbotsScriptPaths 返回随包脚本相对 skills 目录的路径。清单只有一份（就在
// 上面的命令模板里），doctor 预检直接复用它，避免两处漂移。
func HackbotsScriptPaths() []string {
	var out []string
	for _, t := range hackbotsTools() {
		for _, f := range strings.Fields(t.Command) {
			if rel, ok := strings.CutPrefix(f, "{{ARTEX_SKILL_DIR}}/"); ok {
				out = append(out, rel)
			}
		}
	}
	return out
}

// seedHackbotsTools 幂等播种上述工具（首插入生效，用户编辑不被覆盖）。
// 失败只记日志：工具播种不该阻断启动。
func (s *Server) seedHackbotsTools() {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	for _, t := range hackbotsTools() {
		execSpec, err := json.Marshal(commandExec{Command: t.Command, TimeoutMs: 120000})
		if err != nil {
			log.Printf("[hackbots] %s exec 编码失败: %v", t.Key, err)
			continue
		}
		if err := s.m.pg.SeedCustomTool(&db.Tool{
			Key:         t.Key,
			Description: t.Desc,
			Schema:      json.RawMessage(t.Schema),
			Agents:      t.Agents,
			Enabled:     true,
			Kind:        "command",
			Exec:        execSpec,
			Deferred:    true,
		}); err != nil {
			log.Printf("[hackbots] 播种 %s 失败: %v", t.Key, err)
		}
	}
	s.migrateHackbotsToolsNormalized()
}

// migrateHackbotsToolsNormalized 一次性把旧库中 9 个 Hackbots 工具的脚本路径同步到
// 归一化后的 js-api-recon 目录，并开启 deferred=true 折叠冷门工具 schema 减少 token 噪音。
func (s *Server) migrateHackbotsToolsNormalized() {
	const flag = "hackbots_tools_norm_v2"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }()
	for _, t := range hackbotsTools() {
		execSpec, err := json.Marshal(commandExec{Command: t.Command, TimeoutMs: 120000})
		if err != nil {
			continue
		}
		agentsJSON, _ := json.Marshal(t.Agents)
		if _, err := s.m.pg.Exec(`
UPDATE tools
SET description = $2,
    exec = $3,
    agents = $4,
    deferred = true,
    updated_at = now()
WHERE key = $1 AND system = false AND kind = 'command'`, t.Key, t.Desc, execSpec, agentsJSON); err != nil {
			log.Printf("[hackbots] 迁移 %s 失败: %v", t.Key, err)
		}
	}
	log.Printf("[hackbots] 已同步 9 个工具至归一化路径 js-api-recon 并启用 deferred 延迟加载(一次性)")
}

// nodeInterpreter 解析 node：先看 settings 的 node_interpreter，再走 PATH。
// 与 pythonInterpreter 一样，空串表示不可用（升级/未安装），调用方要给出可读错误。
const settingNodeInterpreter = "node_interpreter"

func detectNode() string {
	if p, err := exec.LookPath("node"); err == nil {
		return p
	}
	return ""
}

func (s *Server) nodeInterpreter() string {
	if s != nil && s.m != nil && s.m.pg != nil {
		if v, ok, _ := s.m.pg.GetSetting(settingNodeInterpreter); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return detectNode()
}

// seedNodeInterpreter 开机把探测到的 node 写入 settings（仅空时），不覆盖用户设置。
func (s *Server) seedNodeInterpreter() {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	if v, ok, _ := s.m.pg.GetSetting(settingNodeInterpreter); ok && strings.TrimSpace(v) != "" {
		return
	}
	if p := detectNode(); p != "" {
		_ = s.m.pg.SetSetting(settingNodeInterpreter, p)
		log.Printf("[hackbots] 自动检测到 node 解释器: %s", p)
	}
}

// DetectPythonInterpreter / DetectNodeInterpreter 给 doctor 预检复用同一套探测，
// 避免预检说「有」而运行时说「没有」。
func DetectPythonInterpreter() string { return detectPython() }

func DetectNodeInterpreter() string { return detectNode() }
