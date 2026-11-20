---
name: api-fingerprint-caido
description: 用本机 Caido（默认 127.0.0.1:8080）已捕获的流量，为给定主机发现 API 候选并做 HTTP 指纹：响应头、banner、头顺序、默认错误页、畸形请求、默认文件、Cookie 与路径约定。无流量或服务未启动时返回 blocked，不得臆造指纹。
---

# Caido API 指纹

只读本机 Caido 里已经捕获的流量。Caido 是可选外部服务，默认 `127.0.0.1:8080`。CLI 连不上、没有令牌，或没有该目标的流量时，结果是 blocked / no-data。不得编造主机、技术栈或覆盖矩阵。

不要用浏览器检索、Wappalyzer、Shodan、WhatWeb、Nmap 或其他外部旁证。那些技术在报告里固定写成超出范围。

分析前先读 `${SKILL_DIR}/references/http-fingerprinting.md`。覆盖矩阵是必填项。

## 步骤

1. 从用户最初的请求里取出目标主机或 URL，规范成主机名，但不要假设它就是 API 主机。报告里保留原始目标。最初的请求里没有目标，就停，写一句 blocked。不要追问。

2. 解析 `caido-graphql`。第一行用环境变量，否则用 PATH：

```bash
CAIDO_GRAPHQL_BIN=${CAIDO_GRAPHQL_BIN:-$(command -v caido-graphql)}
```

取不到就报 blocked 并停止。Windows 上改为查看 `CAIDO_GRAPHQL_BIN`，或用 `Get-Command caido-graphql`；生产路径以 Linux 为准。

然后：

```bash
"$CAIDO_GRAPHQL_BIN" status
```

连不上或认证失败时，说明 Caido 应在 `127.0.0.1:8080`，或需要正确的 `--endpoint` / 令牌参数。返回 `INVALID_TOKEN` 时不要交互式索要令牌。报告 blocked，直到当前令牌能通过 `CAIDO_TOKEN`、`CAIDO_ACCESS_TOKEN` 或 `--token-file` 提供。CLI 也会尝试读取 Caido 本地保存的访问令牌。

收集脚本自己也按同一顺序找 CLI：`CAIDO_GRAPHQL_BIN`、PATH 上的 `caido-graphql`，最后才是用户主目录下的历史安装位置。不要依赖最后那一档。脚本找不到二进制或命令失败时，把 stderr 当作 blocked。

3. 查询该目标以及相关兄弟主机：

```bash
python3 ${SKILL_DIR}/scripts/collect_caido_api_traffic.py https://target.example --limit 300
```

默认按相关域搜索。`tesla.com` 这样的目标可以发现 `api.tesla.com`、`owner-api.tesla.com` 和其他 `*.tesla.com` 流量。只有用户明确要求字面主机时才加 `--host-mode exact-host`。需要更窄的过滤时用 `--httpql`。

Windows 上没有 `python3` 时用 `python`。

4. 用输出里的 `api_host_candidates` 和 `host_fingerprints` 确定 API 主机。每个 API 候选都要指纹，并且始终包含字面目标主机，即使它分数低或没有流量。候选多时按主机名分组，分别写分数和理由。

5. 没有流量时，用 `"$CAIDO_GRAPHQL_BIN" operations --filter request` 和 `introspect` 适应 schema 变化，再用更简单的 HTTPQL（例如带引号的相关域字符串）重试一次。仍然没有流量，就结束报告：Caido 里没有相关流量，目标必须先经 Caido 代理浏览之后，本技能才能做指纹。

6. 按参考文档里的 Technique Coverage Matrix 填写。每个被指纹的主机、每一项技术，都要有 covered 或 not-covered。做不到的写原因。

7. 需要主动请求的技术默认不执行。只有最初的请求明确授权了主动测试，且范围清楚时，才生成探针计划并只执行那些低量探针，不要再问一次：

```bash
python3 ${SKILL_DIR}/scripts/plan_http_fingerprint_probes.py https://target.example
```

探针限于：一次 banner GET、一个随机 404、默认文件的 HEAD/GET，以及两次畸形请求解析检查。未授权或授权含糊时，把仅主动的技术标成 not-covered，并把生成的计划当作建议的后续，不要发出。

8. 写简短报告：

- 目标，以及使用的 Caido 过滤条件
- API 发现：搜索的相关域、观察到的全部主机、候选及分数/理由、字面目标主机有没有流量
- 每个主机的 API 面：端点形态、方法、状态码、Content-Type
- 覆盖矩阵：响应头、banner/代理、头顺序、默认错误页、畸形请求、默认文件和目录、Cookie；外部旁证标成超出范围
- 技术线索和证据：头名/值、明确 banner、头顺序、Cookie、响应体短语、默认页、默认文件、扩展名、协议提示，以及只来自 Caido 流量的 CDN/WAF/代理线索
- 置信度：明确的版本、banner 或头值是高；重复出现的 Cookie、头或响应体签名是中；仅头顺序或单条弱线索是低
- 建议的下一步。不做 fuzz，也不做大范围扫描

## Caido 说明

- CLI 默认 GraphQL 端点是 `http://127.0.0.1:8080/graphql`。
- 支持 `--token`、`CAIDO_TOKEN`、`CAIDO_ACCESS_TOKEN` 和 `--token-file`。
- GraphQL schema 会随版本变化。优先用实时 introspection 和本目录的收集脚本，不要把字段名写死。
- HTTPQL 放在 GraphQL 变量里：`{ "filter": { "code": "req.host.cont:\"example.com\"" } }`。
- 收集脚本为每项被动技术给出聚合字段：`api_host_candidates`、`host_fingerprints`、`technology_header_values`、`header_order_guesses`、`default_error_signatures`、`path_and_file_signals`、`cookie_technologies`、`api_paths`，以及每条记录的头、Cookie 和响应体样本。

## 报告规则

- 执行过程中不要追问。用保守默认值继续，或者以清楚的 blocked / no-data 结束。
- 把观察到的事实和推断出的技术分开写。
- 证据只引用短片段。用户没要原始报文就不要贴整包请求或响应。
- 头、Cookie、Authorization、API key 和令牌里明显的秘密要打码。
- 主动探测默认不在流程里。获授权时先写出将要发的探针，并保持低量。
