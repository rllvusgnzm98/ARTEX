---
name: js-api-recon
description: 统一的前端 JS 与 API 攻击面侦察技能：覆盖首屏 JS 抓取、webpack/Vite 懒加载 chunk 重建与下载、正则/AST 级 API 端点与参数提取、SPA 运行时路由与权限树还原、1600 条规则敏感密钥与 DOM XSS 汇聚点扫描，以及可选本地 Caido 代理 API 指纹。适用于所有 Web/SPA 前端接口逆向与 JS 深度审计；不负责企业级外部域名/ASN 测绘（见 tbhm-recon）或单应用热点漏洞推演（见 tbhm-app-analysis）。
---

# JS & API 攻击面统一侦察（js-api-recon）

本技能归一化整合了原有的前端 JS 采集、懒加载 chunk 重建、API 端点/路由/权限树提取、JShero 密钥/DOM-XSS 扫描与 Caido API 指纹流程，按需选择对应层级即可，避免重复造轮子。

## 层级选型（按需选一层，不必全跑）

| 场景 | 推荐入口 | 产出 |
| :--- | :--- | :--- |
| **L1 快速抽端点 / 补全懒加载 chunk** | 延迟工具 `js_extract_endpoints`、`js_lazy_chunks`（或直接运行 `scripts/regex/extract_endpoints.py`、`scripts/chunks/fetch_lazy_chunks.js`） | `all_endpoints.txt`、补齐的 webpack/Vite 懒加载 `.js` |
| **L2 深度 JS 管线（密钥 + DOM XSS + AST 路由台账）** | 延迟工具 `jshero_discover_chunks`、`jshero_extract`、`jshero_scan_findings`、`jshero_merge_runs`、`jshero_build_report`（`scripts/jshero/`） | 按绝对/相对分类的端点表、1600 条规则凭据命中、DOM source→sink 汇聚点、多轮合并报告 |
| **L3 SPA 运行时抓取与权限树还原** | `scripts/spa/`（`harvest_static.py`、`spider_mpa.py`、`runtime_harvest.js`、`extract_route_map.py`、`build_perm_tree.py`） | 静态+动态 API 契约、前端路由表、多角色权限矩阵 |
| **L4 可选本地 Caido 流量 API 指纹** | 延迟工具 `caido_collect_api_traffic`、`http_fingerprint_probe_plan`（`scripts/caido/`；仅本机 Caido `127.0.0.1:8080` 运行时可用，不可用记 blocked，严禁臆造） | HTTP 响应头/banner/错误页指纹与主动探测计划 |

> **工具调用提示**：`js_*`、`jshero_*`、`caido_*`、`http_fingerprint_probe_plan` 为按需延迟工具，可通过 `SearchExtraTools` / `ExecuteExtraTool` 调用，或在 `Bash` 中直接执行 `${SKILL_DIR}/scripts/...` 下的零依赖脚本。需要登录态或真实点击 SPA 触发懒加载 chunk 时，配合平台全局 `browser` MCP（`mcp__browser__*`）或 `playwright-cli` 技能完成首屏交互采集。

## 标准工作流（顺序执行，每步落盘到任务目录 `runs/<domain>/<ts>/`）

1. **保存首屏与静态脚本**：将首页 HTML 与引用的 `.js` 落到 `runs/<domain>/<ts>/raw-js/`（优先只读获取，SPA 动态路由需交互时用 `browser` MCP 配合抓包）。
2. **重建懒加载 chunk（webpack / Vite）**：
   ```bash
   node ${SKILL_DIR}/scripts/chunks/fetch_lazy_chunks.js https://<target>/ --dir runs/<domain>/<ts>/raw-js --dry-run
   # 确认 publicPath 无误后去掉 --dry-run 下载（404 跳过即可）
   ```
3. **提取 API 端点与敏感信息**：
   - 快速正则提取：`python3 ${SKILL_DIR}/scripts/regex/extract_endpoints.py runs/<domain>/<ts>/raw-js`
   - 深度 AST 端点 + 1600 条规则密钥/DOM-XSS 扫描：
     ```bash
     python3 ${SKILL_DIR}/scripts/jshero/discover_chunks.py --run-root runs/<domain>/<ts> --domain <domain> --brute 0
     python3 ${SKILL_DIR}/scripts/jshero/extract_endpoints.py --run-root runs/<domain>/<ts> --domain <domain> --seed https://<target>
     python3 ${SKILL_DIR}/scripts/jshero/scan_findings.py --run-root runs/<domain>/<ts> --domain <domain>
     ```
4. **SPA 路由 / 多角色权限树（复杂后台按需）**：按 `${SKILL_DIR}/references/api-recon-reference.md` 运行 `scripts/spa/` 下的采集与权限树构建脚本。
5. **可选 Caido 指纹（仅本机有 Caido 抓包时）**：先读 `${SKILL_DIR}/references/http-fingerprinting.md`，再调用 `caido_collect_api_traffic` / `http_fingerprint_probe_plan`。

## 附加参考（按需读取）

- `${SKILL_DIR}/references/surface-checklist.md`：分步交付验收清单
- `${SKILL_DIR}/references/api-recon-reference.md`：SPA 路由、静态/运行时采集与权限树参考手册
- `${SKILL_DIR}/references/http-fingerprinting.md`：HTTP 指纹分析矩阵与主动探测边界
