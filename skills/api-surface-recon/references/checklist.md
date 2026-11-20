# API 攻击面侦察检查表

三步都做完再声称侦察完成。某一步被环境挡住时，写明 blocked 和原因，不要用空表格冒充结果。

## 步骤 1 — 目标与 base URL

- [ ] 用户给出的原始目标（URL 或主机）已原文记下
- [ ] 首屏已保存（`/tmp/page.html`，或 Windows 上的 `runs/<domain>/<ts>/page.html`）
- [ ] 重定向之后的 origin 已解析
- [ ] 静态资源 base URL 已解析（与 origin 不同时单独写）
- [ ] 首屏 `<script src>` 和能看出的 publicPath 已列出
- [ ] 首屏 JS 已落在 `runs/<domain>/<ts>/raw-js/`
- [ ] 若用了 `browser` MCP：补记的脚本 URL 与 XHR/fetch 主机已写入笔记。没启用则明确写「仅静态」

## 步骤 2 — chunk

- [ ] 先做了 dry-run，再下载
- [ ] 实际使用的 base URL 包含 dry-run 看到的 publicPath（或说明 publicPath 已经在 chunk 相对路径里）
- [ ] chunk 总数
- [ ] ok 数量与 FAIL 数量（含 HTTP 404）
- [ ] 落盘目录

## 步骤 3 — 端点

- [ ] `all_endpoints.txt` 的路径和去重后的端点总数
- [ ] 四组各有多少：`/api` 路由、绝对 URL、AJAX/fetch 目标、IDOR 候选
- [ ] 高价值线索（SSRF、IDOR、开放重定向）逐条列出，并带上参数名（`id`、`url`、`redirect` 等）
- [ ] 静态资源和第三方主机已说明被滤掉，而不是混在主列表里
- [ ] 若看到 `API_BASE` 或 `baseURL`，写明用它还原了哪些相对路径

## 步骤 3 — 指纹（可选）

Caido 不可用或没有该目标的流量时，整节写 blocked，其余格子留空。

- [ ] 状态：完成，或 blocked（写明是 CLI 找不到、连不上 `127.0.0.1:8080`，还是没有流量）
- [ ] 使用的 HTTPQL / 过滤条件，以及搜索的相关域
- [ ] 观察到的主机，和 API 候选（主机、分数、理由）
- [ ] 字面目标主机是否有流量
- [ ] 每个被指纹的主机：端点形态、方法、状态码、Content-Type
- [ ] 覆盖矩阵。每个主机都要说明下列技术是 covered、not-covered，还是超出本技能范围：
  - 响应头
  - banner / 反向代理
  - 头顺序
  - 默认错误页
  - 畸形请求行为
  - 默认文件和目录
  - Cookie
  - 外部旁证（本技能固定为超出范围，不查第三方）
- [ ] 技术线索：证据原文（短）、置信度（高 / 中 / 低）
- [ ] 建议的下一步只包括被动或低量检查。未获授权的主动探测标成未覆盖，并附上探针计划，不要执行
