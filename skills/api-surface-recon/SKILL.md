---
name: api-surface-recon
description: 已授权 API 攻击面的顺序侦察：确认目标并保存首屏，下载懒加载 chunk，提取端点，并在 Caido 可用时做 API 指纹。由单个执行者按文件与命令行完成。Caido 未启动时该步记为 blocked，不得臆造结果。
---

# API 攻击面侦察

在**已授权**前提下，把一个目标的前端脚本收成端点清单。下面三步按顺序做，每步的路径和计数写下来再进入下一步。整个流程由当前这一个执行者用文件和命令行完成。

浏览器 MCP 是可选的。当前会话没有名为 `browser` 的 MCP 时，第一步只做静态保存，不要假装已经点过 SPA。

Caido 是可选外部服务，默认 `127.0.0.1:8080`。没启动，或没有该目标的流量时，指纹记为 blocked。端点提取照常做完。不得编造主机或技术栈。

每步要交什么，见 [references/checklist.md](references/checklist.md)，也就是 `${SKILL_DIR}/references/checklist.md`。

## 步骤 1 — 确认目标并取首屏

目标必须是用户给出的 URL 或主机。没有目标就停下询问，不要猜。

Linux / 容器里保存首屏和响应头：

```bash
mkdir -p "runs/<domain>/<ts>/raw-js"
curl -sS -D- -o /tmp/page.html "https://<host>/"
```

Windows 没有 `/tmp` 时，把 HTML 改存到 `runs/<domain>/<ts>/page.html`。

从 HTML 里记下：

- 重定向之后的 origin，以及静态资源的 base URL
- `<script src>` 指向的 bundle
- 能看出的 publicPath（例如 `/static/js/` 或 CDN 主机）

若 `browser` MCP 已启用，用它打开同一 URL，补记首屏实际加载的脚本 URL，以及加载过程中的 XHR/fetch 主机。没启用就用 curl 的结果继续。

把首屏 JS 下载到 `runs/<domain>/<ts>/raw-js/`。这一步只落盘，不提取端点。

## 步骤 2 — 下载懒加载 chunk

按 `lazy-chunk-downloader` 技能执行。base URL 用步骤 1 解析出的 origin（若 publicPath 是子路径或 CDN，把 base 指到真实资源根）。`--dir` 用 `runs/<domain>/<ts>/raw-js`。先 dry-run，看 publicPath，再去掉 dry-run 下载。

记下 chunk 数量、检测到的 publicPath、ok 与 FAIL 的数量、文件落在哪个目录。`HTTP 404` 记入 FAIL 后继续。

## 步骤 3 — 端点提取，以及可选的 API 指纹

按 `js-endpoint-extraction` 技能，对 `runs/<domain>/<ts>/raw-js` 提取。执行前进入该 run 目录，或把标准输出重定向过去，使 `all_endpoints.txt` 落在 run 目录而不是仓库根。

分类保持该技能的四组：`/api` 路由、绝对 URL（SSRF / 开放重定向）、AJAX/fetch 目标、带 id 或 token 的路径（IDOR）。滤掉静态资源和第三方主机。

Caido 可用时，再按 `api-fingerprint-caido` 技能对用户给出的原始目标做指纹。它自己从流量里找 API 主机，不依赖步骤 1 的 base URL。Caido 没启动或没有流量时，把指纹写成 blocked，然后结束。不要为了指纹去改前两步的结果。

## 交付

对照检查表汇总：访问的目标、解析出的 base URL、chunk 的 ok/FAIL、端点数量和高价值线索、指纹是完整覆盖矩阵还是 blocked。
