---
name: blind-oracle-extractor
description: 当手工确认存在布尔盲注、时间盲注、报错截断或状态长度预言机，且通用工具难以处理自定义 JSON/数组参数格式、双重编码或网络抖动时加载：先执行基线 RTT 分布与真假响应分离度校准，再以受控并发与二分/半字节搜索提取并落盘断点。
---

# 盲注预言机校准与高效提取（blind-oracle-extractor）

适用于布尔盲注、时间盲注与自定义 HTTP 预言机场景。核心纪律：**未经统计校准绝不直接跑固定 `sleep` 阈值盲抽；提取长字段时先落盘检查点，防预算中断丢失进度。**

## 标准化作业流

1. **先校准基线 RTT 与真假分离度**（5~10 次采样即可）：
   ```bash
   python3 ${SKILL_DIR}/scripts/oracle_calibrate.py https://target.example.com/api/item --dry-run
   ```
   - 若仅测网络 RTT 基线（计算 p50 / p95 / IQR，给出时间盲注安全阈值 `>= max(3 * p95, p95 + 1000ms)`）：
     ```bash
     python3 ${SKILL_DIR}/scripts/oracle_calibrate.py https://target.example.com/ --samples 6
     ```
   - 若已构造好真/假对比 URL（`--true-url` 与 `--false-url`），脚本同时验证状态码/响应长度是否稳定二分、是否存在抖动重叠。
2. **提取编码策略**：
   - 确认可二分分离后，优先使用 `ASCII` 二分搜索（每字符仅需 7 次探测，而非 95 次线性遍历）或 4-bit hex 半字节并发提取；
   - 保持并发度受控（默认 4 线程），遇到连续 429/502/503 立即退避降速；
   - 已确认前缀写入当前意图目录 `blind_state.json`，即便交接下一波次也能从断点继续。
