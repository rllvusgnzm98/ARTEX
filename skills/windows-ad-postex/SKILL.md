---
name: windows-ad-postex
description: Windows 与 Active Directory 授权后渗透阶段的资产盘点、产物去重与共享目录治理清单：采集前先检查 <taskDir>/shared/ 避免重复作业、按 <taskDir>/shared/loot_<host>/ 规范落盘并生成清单、以有界精准检索替代全盘盲扫、并统一去重登记凭据与 artifact_paths。
---

# Windows / AD 后置盘点与产物去重规范（windows-ad-postex）

在多单兵协同的授权内网评估中，最常见的效率黑洞是 **不同单兵反复对同一主机采集相同产物、执行无边界全盘搜索拖垮目标或触发超时**，以及 **原始输出散落在私有目录导致凭据与证据重复登记**。本技能建立统一的 `<taskDir>/shared/` 检索、归档与去重规范。

---

## 边界与治理纪律（Agent 必读）

| 治理维度 | 强制要求 | 严格禁止 |
|---|---|---|
| **先查再采（防重复）** | 采集任何主机产物前，必须先运行 `scripts/hive_loot_parse.py scan --shared-dir <taskDir>/shared --target-host <host>` 检查是否已有记录 | 跳过 `shared/` 盘点直接对已采集主机重复拉取同一批文件或配置 |
| **统一落盘结构** | 单机产物统一存入 `<taskDir>/shared/loot_<host>/`（主机名仅保留字母数字与下划线）并生成 `manifest.json` | 将下游需复用的产物遗留在单兵私有 `i<id>/` 目录或随意命名覆盖旧文件 |
| **有界精准检索** | 文件检索必须限定目标目录、递归深度、扩展名白名单与文件大小上限 | 执行无边界全盘扫描（如 `dir /s C:\`、`Get-ChildItem -Recurse C:\`），避免耗时超时与主机 I/O 抖动 |
| **凭据去重与溯源** | 先本地解析去重并核对 `list_credentials`，再通过 `add_credential` / `record_fact` 登记，必须携带 `artifact_paths` | 未去重直接批量灌入重复凭据，或只写口头结论却不留存可审计的 `artifact_paths` |

---

## 四步标准化作业流

### Step 1: 采集前先索引 `<taskDir>/shared/`

在连接目标主机执行收集动作之前，先检查共享目录中已有哪些主机与产物文件：

```bash
python3 ${SKILL_DIR}/scripts/hive_loot_parse.py scan \
  --shared-dir /path/to/taskDir/shared \
  --target-host 10.10.20.10
```

- 若返回 JSON 中 `target_already_collected: true` 且所需类别（如主机基线、配置快照、结构化输出）已存在，**直接读取现有文件并跳过重复采集**。
- 检查 `duplicate_files` 字段，及时识别跨目录的重复副本。

### Step 2: 有界精准文件检索（禁止全盘盲扫）

当确需补充采集应用配置或运维文件时，必须遵守有界策略：

1. **先锁定业务路径**：从运行服务、IIS/Web 根目录、计划任务、环境变量或已知应用目录入手，而非根目录 `C:\`。
2. **显式排除高噪系统目录**：跳过 `C:\Windows\WinSxS`、`C:\Windows\System32`、`C:\Program Files\Common Files`、`node_modules`、`.git\objects`。
3. **强制深度与数量上限**：限制递归深度（如 `<= 3` 层）、限制单文件读取大小（如 `<= 1MB`）与返回条目上限（如最多 50 条匹配）。
4. **落盘命名**：所有合法采集结果按 `<taskDir>/shared/loot_<host>/<category>_<timestamp>.<ext>` 写入共享目录（只增不删）。

### Step 3: 本地结构化解析、去重与清单生成

对已经落盘在 `<taskDir>/shared/` 下的本地文本、键值、JSON/JSONL 或冒号分隔结构化导出文件执行离线解析与去重（脚本仅读取本地文件，不接触任何远程目标或系统内存）：

```bash
# 1. 解析并去重本地共享目录中的结构化输出（可加 --mask-secrets 生成脱敏摘要）
python3 ${SKILL_DIR}/scripts/hive_loot_parse.py parse \
  --shared-dir /path/to/taskDir/shared \
  --mask-secrets

# 2. 为指定主机目录生成或刷新 manifest.json 与标准 artifact_paths 列表
python3 ${SKILL_DIR}/scripts/hive_loot_parse.py manifest \
  --loot-dir /path/to/taskDir/shared/loot_10_10_20_10 \
  --host 10.10.20.10 \
  --write
```

### Step 4: 平台登记与跨单兵交接

1. 调用 `list_credentials` 比对当前任务已登记条目，仅将**去重后的新增有效凭据**通过 `add_credential` 入库。
2. 调用 `record_fact` 沉淀关键主机信息与清单摘要，并将 `manifest` 命令输出的 `artifact_paths` 绝对路径完整填入 `record_fact.artifact_paths`，确保后续单兵进场自动感知已有产物。

---

## 交付检查清单 (Definition of Done)

- [ ] 采集前已通过 `hive_loot_parse.py scan` 核查 `<taskDir>/shared/`，未对已有主机重复采集。
- [ ] 全程采用有界目录与深度限制，未触发全盘阻塞式扫描。
- [ ] 所有产物均已归档至 `<taskDir>/shared/loot_<host>/` 并生成 `manifest.json`。
- [ ] 已完成本地去重，核对 `list_credentials` 后再登记新增凭据，且 `record_fact` 已附带绝对 `artifact_paths`。
