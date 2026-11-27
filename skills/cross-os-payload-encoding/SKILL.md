---
name: cross-os-payload-encoding
description: 跨平台（Linux/Bash 向 Windows cmd/PowerShell）命令转义、PowerShell 版本兼容性核查、UTF-16LE -EncodedCommand 编码与大脚本分片 SHA256 校验落盘规范。适用于需要通过远端 Shell 或跨系统通道稳定执行多行脚本与含特殊符号命令的场景；严禁在双引号 Bash 字符串中裸拼未转义的 $ 变量或跳过目标版本检测。
---

# 跨平台命令编码与转义规范（cross-os-payload-encoding）

在 Linux 控制端向 Windows 目标（`cmd.exe`、`powershell.exe`、`pwsh`）传递命令或脚本时，最常见的失败原因并非目标不可达，而是 **Bash 双引号提前展开 `$` 变量、引号嵌套破坏、PowerShell v2/v3+ 语法不兼容** 或 **命令行长度截断**。本技能通过确定性预检与编码工具消除跨 OS 语法损耗。

---

## 边界与纪律（Agent 必读）

| 维度 | 允许与推荐做法 | 严格禁止 |
|---|---|---|
| **Bash 引号转义** | 使用单引号包裹、heredoc 传入文件，或用 `scripts/encode_ps.py` 生成 UTF-16LE Base64 `-EncodedCommand` | 在 Bash 双引号 `"..."` 中直接内联未转义的 `$env:`、`$PSVersionTable`、`$_` 等 PowerShell 变量 |
| **版本前置探测** | 先探测目标 Shell 与 PowerShell 主版本（`$PSVersionTable.PSVersion.Major`），再决定可用参数与 Cmdlet | 未检查版本就在 Windows Server 2008/2012 上盲用 v3+ 特性（如 `Invoke-WebRequest`、`ConvertFrom-Json`、`Get-Content -Raw`、`$PSScriptRoot` 或不安全的 `-File` 混合引号调用） |
| **多行脚本传输** | 超过 2 行或编码后接近 `cmd.exe` 8191 字符上限的脚本，采用分片 Base64 写入并执行 SHA256 一致性校验 | 直接将多行脚本拼为超长单行命令造成静默截断、换行符丢失或编码损坏 |

---

## 标准作业流程

### Step 1: 探测目标 Shell 与 PowerShell 版本

在执行任何复杂命令前，先以最小只读探针确认目标环境：

- **确认 Shell 与 PowerShell 版本**：
  - `powershell.exe -NoProfile -NonInteractive -Command "$PSVersionTable.PSVersion.Major"`（在 Bash 中外层必须使用**单引号** `'$PSVersionTable.PSVersion.Major'`！）
  - 兼容 PowerShell v2 的写法：避免使用 `Invoke-WebRequest`、`Invoke-RestMethod`、`ConvertFrom-Json`、`ConvertTo-Json`、`Get-Content -Raw`、`Compress-Archive`、`$PSScriptRoot`、`Using:` 作用域及 `ForEach-Object -Parallel`。
  - 注意 `cmd.exe` 单条命令行上限为 **8191 字符**；跨跳代理或 Web 控制台通道可能具备更严格的请求体/参数上限。

### Step 2: 编码模式选型矩阵

| 场景特征 | 推荐模式 | 对应脚本参数 | 校验方式 |
|---|---|---|---|
| **1–2 行命令**（含 `$`、单双引号、管道符） | UTF-16LE `-EncodedCommand` | `--mode encoded` | `--verify-roundtrip` 验证无损往返 |
| **旧版 PowerShell v2 目标** | 启用 v2 兼容性静态检查 | `--ps-version 2` | 阻断/告警所有 v3+ Cmdlet 与参数风险 |
| **多行脚本（>2 行）或超长命令行** | 分片 Base64 落盘计划 | `--mode chunked --chunk-size 2048` | 逐片计数 + 落地文件 SHA256 比对 |
| **自动决策** | 由脚本按行数与字符上限自动选择 | `--mode auto` | 输出完整诊断 JSON 与建议命令 |

### Step 3: 使用确定性工具生成安全命令或分片计划

所有工具均仅依赖 Python 3 标准库，输出结构化 JSON，不直接向目标发送流量：

```bash
# 1. 对含 $ 变量与引号的短命令执行兼容性检查并生成 UTF-16LE -EncodedCommand
python3 ${SKILL_DIR}/scripts/encode_ps.py \
  --command 'Get-Process | Where-Object { $_.CPU -gt 10 } | Select-Object -First 5 Name,Id' \
  --ps-version 2 \
  --mode encoded \
  --verify-roundtrip

# 2. 对多行本地脚本自动生成带 SHA256 校验的分片传输计划
python3 ${SKILL_DIR}/scripts/encode_ps.py \
  --file /path/to/local_inventory.ps1 \
  --ps-version 2 \
  --mode auto \
  --chunk-size 1536 \
  --target-path 'C:\Windows\Temp\inventory.ps1'
```

### Step 4: 落地校验与清理

1. 采用分片写入时，**必须**在目标端对合并后的文件计算 SHA256，与 `encode_ps.py` 输出的 `expected_sha256` 完全一致后方可执行。
2. PowerShell v4+ 可使用 `Get-FileHash -Algorithm SHA256`；PowerShell v2 请使用 `[System.Security.Cryptography.SHA256]::Create()`（脚本输出中已附带对应校验片段）。
3. 临时落盘文件使用完毕后记录路径并在收尾阶段清理，避免残留垃圾文件。

---

## 交付检查清单 (Definition of Done)

- [ ] 已确认目标 Shell 类型与 PowerShell 主版本号（必要时显式传 `--ps-version 2`）。
- [ ] 所有含 `$` 或嵌套引号的命令均已通过 `encode_ps.py` 检查，无 Bash 双引号提前展开风险。
- [ ] 命令行长度未超过目标通道上限（默认按 `cmd.exe` <= 8000 字符兜底）。
- [ ] 超过 2 行的脚本已通过分片计划传输并完成 SHA256 一致性校验。
