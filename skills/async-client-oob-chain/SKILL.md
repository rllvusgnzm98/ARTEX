---
name: async-client-oob-chain
description: 当目标存在存储型/反射型/DOM XSS、CSRF、postMessage、开放重定向或管理员/受害者机器人延迟触发链路时必须加载：使用平台托管 OOB 端点（oob_allocate/oob_poll）与 browser MCP 做分阶段遥测与导航中断存活验证，禁止无回连盲猜。
mcps: browser
---

# 异步客户端与 OOB 联动验证（async-client-oob-chain）

适用于**管理员机器人触发、异步存储型 XSS、CSRF 提权与 OOB 回调链路**。核心教训：**切勿针对仅返回 true/false 的验证端点盲改载荷，先用托管 OOB 把浏览器侧真实 DOM、路由与错误信息打回来。**

## 三阶段标准化作业流

1. **申请平台托管 OOB 端点（禁止在 Bash 起 python HTTP 占端口）**：
   - 调用 `oob_allocate(label="xss-bot-telemetry")`，拿到平台持久化回调 URL（`/o/<token>`，按目标可达地址调整主机）。
   - 若需要下发较长 stage-2 逻辑，可在 `oob_allocate` 指定 `response_content_type="application/javascript"` 与 `response_body`。
2. **分阶段遥测 + 导航中断存活**：
   - **Stage 1（证明执行）**：用 `navigator.sendBeacon()`、`fetch(..., {keepalive:true})` 或同源同步 XHR 发送心跳，防止机器人浏览页面后立即跳转导致异步请求被 abort。
   - **Stage 2（回传真实运行时态）**：在同源脚本里采集目标页面的 `document.title`、HTTP 状态码、侧边栏真实 `href` 与 URL/表单 CSRF `_token` 写回 OOB（线上容器与静态 `db.sql`/源码常有路由前缀或预设账号差异）。
   - **Stage 3（精准完成状态变更）**：用 `oob_poll(token=..., wait_seconds=15)` 读取真实字段后，按实测路由与 `_token` 完成单步提权/操作并回收证据。
3. **本地 DOM / CSP 核验**：
   - 使用已解锁的 `mcp__browser__*` 工具提前验证内容嗅探、CSP 限制与 `FormData` 编码细节，再用 `oob_diag.py` 检查本地导出的 JSONL 回调记录或 CORS 头。

```bash
python3 ${SKILL_DIR}/scripts/oob_diag.py --help
```
