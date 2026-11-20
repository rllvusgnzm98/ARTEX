# Hackbots 脚本来源

`skills/` 里下面这些目录来自课程材料 *ArcanumSec — Hackbots (using Agent Frameworks) 2026* 的 Hackbots Toolkit：

- `js-endpoint-extraction`
- `lazy-chunk-downloader`
- `jshero`
- `content-discovery-wordlist`
- `api-surface-recon`
- `api-fingerprint-caido`

接入时只做了解耦，没有改扫描规则本身：

- 去掉写死的本机路径、Codex / Claude 工作流，以及会去调用外部 agent 的桥。
- 说明改写成 ARTEX 的 `SKILL.md`，脚本路径用 `${SKILL_DIR}`。
- `jshero/scripts/secrets_patterns.json` 只整理了格式，规则条目与原文件一致。
- Caido 采集脚本改为先看 `CAIDO_GRAPHQL_BIN`，再在 `PATH` 里找 `caido-graphql`。找不到就退出并说明原因，不编造流量。

未迁入 `interceptor`、`say_hello`、外部 agent 定义，以及写死了他人机器和 VPS 的 `jshero-5x.workflow.js`。

这些脚本仍是课程材料的衍生作品。本仓库其余代码是 AGPL-3.0；若课程材料的许可与 AGPL-3.0 不一致，把它们打进对外发布的镜像或压缩包之前，需要自行确认再分发权。
