---
name: jshero
description: 对已授权目标收集 JavaScript 并做静态分析：下载懒加载 chunk、重建 webpack chunk 文件名、按内容哈希合并多次采集、提取端点并扫描敏感信息与 DOM 汇聚点。产物在任务目录 runs/<domain>/<ts>/。历史归档仅在本机有 waymore 时可选。
---

# jshero

在**已授权**前提下，把一个目标的 JavaScript 收进任务目录，再做端点、参数、敏感信息和 DOM 汇聚点分析。没下载到的文件就是没看到的攻击面，所以采集要做完；但本技能只使用仓库里的脚本、`lazy-chunk-downloader`，以及可选的 `browser` MCP。

历史归档是可选项：本机有 `waymore` 才做。用 `command -v waymore` 探测。没有就在 `manifest.md` 里写明跳过，不要改走别的主机。

浏览器 MCP 没启用时，第一阶段只做静态：保存首屏并下载懒加载 chunk。不要假装已经点击过 SPA。

## 边界

| 范围 | 允许 | 禁止 |
|---|---|---|
| 目标 | 用户给出的种子 URL 或裸域名。裸域名时种子用 `https://<domain>` | 扩大到未授权主机；把第三方 CDN 的业务端点写进主列表 |
| 采集 | 首屏、懒加载 chunk、可选的本机 waymore | 为了「全量」去连固定服务器或写死 SSH |
| 分析 | 端点分类、参数、敏感信息、DOM 汇聚点、HTML 报告 | 在本技能里做漏洞利用 |

`<domain>` 取可注册域名，`<host>` 取种子的精确主机，`<ts>` 取运行开始时的 `YYYYMMDD-HHMMSS`。

## 输出布局

全部写在任务工作目录，不要写到家目录或临时盘根：

```
runs/<domain>/<ts>/
  raw-js/            外部 JS 与 chunk
  inline-js/         内联脚本
  historical-js/     可选，waymore 拉回的归档体
  passes/pass-N/     多次独立采集时，每遍自己的 raw-js 与 inline-js
  _meta/             来源说明
  manifest.md
```

账本在 run 目录的上一级：`runs/<domain>/ledger.json`。提取脚本默认就是这个位置。不要在两次运行之间删它，它用来只报告新出现的端点和参数。

开始时创建目录：

```bash
mkdir -p "runs/<domain>/<ts>/raw-js" "runs/<domain>/<ts>/inline-js" \
  "runs/<domain>/<ts>/historical-js" "runs/<domain>/<ts>/_meta"
```

## 阶段 1 — 收集

1. 保存首屏。Linux / 容器：

```bash
curl -sS -D- -o /tmp/page.html "https://<host>/"
```

Windows 没有 `/tmp` 时，HTML 改存到 `runs/<domain>/<ts>/page.html`。记下重定向后的 origin、脚本 URL 和 publicPath。若 `browser` MCP 已启用，用它打开种子 URL，把首屏和触发到的脚本 URL 补进 `raw-js/`。没启用就只做静态。

2. 下载懒加载 chunk。按 `lazy-chunk-downloader` 技能：先 dry-run 看 publicPath，再下载。`--dir` 用 `runs/<domain>/<ts>/raw-js`，base URL 用上一步的资源根。404 记入 FAIL 后继续。

3. 可选：历史 JS。只有本机有 waymore 才做。

```bash
if command -v waymore >/dev/null 2>&1; then
  waymore -i "<domain>" -mode U -oU "runs/<domain>/<ts>/_meta/waymore-all-urls.txt"
  waymore -i "<domain>" -mode B \
    -mt "application/javascript,text/javascript,application/x-javascript,text/x-javascript,application/ecmascript,text/ecmascript" \
    -ci none -l 0 \
    -oU "runs/<domain>/<ts>/_meta/waymore-js-urls-mime.txt" \
    -oR "runs/<domain>/<ts>/historical-js"
else
  echo "optional historical stage skipped: waymore not installed"
fi
```

大目标可以先把 `-l` 降到 `5000` 或改用 `-ci d`（每天一份），再放宽。无扩展名的响应体在本地改成 `.js`。waymore 不在 PATH 上就跳过，并在 manifest 里写原因。

## 阶段 2 — 静态 chunk 发现

对已经收集的 bundle 重建 webpack chunk 文件名。这一步不依赖页面点击：

```bash
python3 ${SKILL_DIR}/scripts/discover_chunks.py \
  --run-root "runs/<domain>/<ts>" \
  --domain "<domain>"
```

产物：`chunk-candidates.txt`、`chunk-urls.txt`、`chunk-summary.json`。把 `chunk-urls.txt` 里的 URL 用 curl 拉到 `raw-js/`（404 跳过）。新文件若还含有 chunk 映射，再跑一次 `lazy-chunk-downloader`。Windows 上没有 `python3` 时用 `python` 调用同一个脚本。

## 阶段 3 — 合并去重

一次采集把文件直接放在 run 根的 `raw-js/` 和 `inline-js/`，不必合并。

多次采集时，每一遍用独立目录，不要混在同一个文件夹里增量覆盖：

```
runs/<domain>/<ts>/passes/pass-1/raw-js
runs/<domain>/<ts>/passes/pass-1/inline-js
runs/<domain>/<ts>/passes/pass-2/raw-js
runs/<domain>/<ts>/passes/pass-2/inline-js
```

然后按内容哈希去重，合并到 run 根：

```bash
python3 ${SKILL_DIR}/scripts/merge_runs.py --runset-root "runs/<domain>/<ts>"
```

看 `merge-summary.json`。若最后几遍新增哈希接近 0，采集可以停。若最后一遍仍在增加文件，再加一遍独立目录后重新合并。历史 JS 只收集一次，放在 run 根的 `historical-js/`，不要复制进每一遍。

## 阶段 4 — 端点、敏感信息、汇聚点

模式库和扫描脚本在同一目录：`${SKILL_DIR}/scripts/secrets_patterns.json`。`scan_findings.py` 默认读它，不要另找一份。

```bash
python3 ${SKILL_DIR}/scripts/extract_endpoints.py \
  --run-root "runs/<domain>/<ts>" \
  --domain "<domain>" \
  --seed "https://<host>/"
python3 ${SKILL_DIR}/scripts/scan_findings.py \
  --run-root "runs/<domain>/<ts>" \
  --domain "<domain>"
python3 ${SKILL_DIR}/scripts/build_report.py \
  --run-root "runs/<domain>/<ts>" \
  --domain "<domain>"
```

提取脚本扫描 `raw-js/`、`inline-js/`、`historical-js/`，把链接分成四类：

1. **full** — `https://...` 和协议相对的 `//...`
2. **absolute_or_dotted** — `/*`、`./*`、`../*`、`#/*`
3. **relative_with_slash** — `path/to/file.php`
4. **relative_no_slash** — 带扩展名的 `file.php`

主列表只要目标域及其子域。第三方主机写到 `endpoints-thirdparty.txt`，不进账本。另外会写出：

- `endpoints-all.txt` / `endpoints-new.txt` — 全部 / 账本里没有的
- `endpoints-methods.txt` — 能还原 HTTP 方法的目标端点
- `params-all.txt` / `params-new.txt`
- `reseed-urls.txt` — 新的范围内绝对 URL。要继续扩面时，把它们当作下一遍的种子，下载进新的 `passes/pass-N/`，再回到阶段 3 合并
- `extract-summary.json`

请求配置提取覆盖 `fetch`、`XMLHttpRequest.open`、`$.ajax` 和 `axios`。模板字符串里的动态段会收成带 `EXPR` 的骨架，整串都是 `EXPR` 的丢掉。参数只从真实 query 和配置对象里取。

敏感信息扫描读 `secrets_patterns.json`。DOM 汇聚点是正则，不是 AST，置信度要在报告里写明。产物：`secrets-all.txt`、`secrets-new.txt`、`sinks-all.txt`、`sinks-new.txt`、`findings-summary.json`。单文件超过 4MB 会跳过敏感信息扫描。

`build_report.py` 在 run 根写自包含的 `report.html`（端点、参数、JS 数量、方法、chunk、分遍收敛）。

`reseed-urls.txt` 若还有新的页面型 URL，用阶段 1 的方式再收一遍（新的 pass 目录），然后重新合并并再跑本阶段。停止条件是一轮下来 0 个新 JS 哈希、0 个新端点、0 个新参数、0 个新 chunk。迭代上限建议 8 轮；碰到上限就在 manifest 里写还剩什么，不要假装已经收敛。

## manifest 与完成定义

`manifest.md` 至少包含：种子、`<domain>`、`<host>`、`<ts>`；首屏与 chunk 的 ok/FAIL；waymore 是执行了还是跳过；端点四类计数、新端点、参数、reseed；chunk 文件名数量；`raw-js`、`inline-js`、`historical-js` 的文件数；若做了多遍，写上 `merge-summary.json` 里每一遍的新增哈希。

完成前核对：

- [ ] 懒加载 chunk 已按 publicPath 下载，404 有计数
- [ ] 多遍采集是「每遍独立目录 + `merge_runs.py` 哈希去重」，没有把多遍混进同一个目录
- [ ] 历史阶段要么有 waymore 产物，要么 manifest 写了跳过
- [ ] `extract_endpoints.py`、`scan_findings.py`、`build_report.py` 都跑过，账本还在 `runs/<domain>/ledger.json`
- [ ] 主端点列表没有混入第三方主机
