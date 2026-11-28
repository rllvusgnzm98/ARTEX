---
name: target-health-triage
description: 当目标出现 HTTP 502/503/504、连接拒绝或超时、全路径返回一致 403/200、或怀疑限速/Tarpit 延迟时加载：通过 3 点对照矩阵在数秒内确定性区分「基础设施/上游不可用」「WAF 统一拦截」「Tarpit 人为延迟」与「应用层真实异常」，并输出熔断或转向决策。
---

# Target Health Triage（目标健康度与 503/WAF/Tarpit 分诊）

面向企业攻防演练、漏洞赏金与靶场环境。核心原则：**遇到连续 502/503/连接故障时，用 3 次低噪声对照在数秒内完成定位并快速熔断，严禁通过 `sleep` 死等耗尽单兵运行预算。**

## 边界与纪律

1. **三点只读对照**（不对目标做高频并发或破坏性发包）：
   - 点 A：根路径或已知正常页面 `GET`
   - 点 B：随机不存在路径 `GET`（404 / catch-all 基线）
   - 点 C：带无害查询参数路径 `GET`（如 `?q=artex_probe`）
2. **禁止死循环重试**：一旦确认上游 `503 resource_unavailable` / TCP 不可达且间隔退避重试仍失败，立即调用 `record_fact(category="scope_limit", confidence="observed")` 如实写回阻塞状态并结束本意图，交由规划者降权或挂起。熔断收队即闭环：本 worker 立即结束释放预算，**不要**驻留、轮询或 `sleep` 等待目标恢复——是否值得回捡、何时回捡，由规划者以低频长间隔的看门哨意图接力；你要做的只是把可用信号（如疑似恢复时间窗、限流阈值特征）一并写进 fact detail 供接力单使用。

## 执行分诊

```bash
# 对目标执行 3 点健康分诊（支持 --dry-run）
python3 ${SKILL_DIR}/scripts/health_triage.py https://target.example.com/
```

## 结论处置矩阵

| `verdict` | 特征信号 | 推荐动作 |
|---|---|---|
| `infra_unavailable` | 全路径返回 502/503/504、连接拒绝或 DNS/TCP 超时 | 短暂退避重试 1~2 次仍失败 -> `record_fact(category="scope_limit")` 熔断退出并立即收队（恢复探测交由规划者的看门哨意图接力，不驻留等待） |
| `uniform_filter` | 点 A/B/C 返回几乎完全一致的状态码与正文长度/哈希（如统一 403/拦截页） | 存在边缘统一拦截（WAF/CDN），切换源站 IP、协议端口或鉴权入口 |
| `tarpit_delay` | 点 A 快速返回、带特征请求固定卡齐整秒数延迟（如均 >= 3s） | 弃用时间盲注判据，改用内容差异或 OOB 回调验证 |
| `healthy_app` | 点 A/B/C 状态码/长度明显分化或正常响应 | 业务后端可达，继续按既定攻击假设推进 |
