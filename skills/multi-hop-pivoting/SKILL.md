---
name: multi-hop-pivoting
description: 多跳内网代理与端口转发操作清单：先被动采集网卡/路由/ARP/监听端口，合理区分单端口转发与 SOCKS5 代理，绑定前检查本地端口冲突，强制通过 tunnel_register 与 shared/tunnels.json 纳管通道，严禁在无有效路由时盲扫不可达内网网段。
---

# 多跳内网代理与路由纪律（multi-hop-pivoting）

跨网段多跳评估的核心风险是 **无路由盲打浪费预算、本地端口绑定冲突、重复搭建冗余隧道** 以及 **缺乏清理台账**。本技能通过“先被动拓扑盘点 -> 冲突预检 -> 通道选型与验证 -> 统一纳管”的四步闭环确保多跳链路稳定可复用。

---

## 边界与路由纪律（Agent 必读）

| 纪律项 | 强制要求 | 严格禁止 |
|---|---|---|
| **先被动采集拓扑** | 建隧道前先收集网卡、路由表、ARP/邻居表与本机监听端口 | 尚未掌握多网卡拓扑与可达网段就盲目搭建代理或发起扫描 |
| **严禁无路由盲打** | 仅对经路由表或已验证隧道明确可达的网段发起探测 | 在没有活跃路由/隧道的情况下直接探测隔离内网段（导致大量超时与 RoE 噪音） |
| **本地端口防冲突** | 绑定任何监听端口前，先运行 `scripts/pivot_check.py port-check` 确认空闲 | 未检查端口占用就强行绑定 `1080`/`8080`/`8443` 造成启动失败或劫持现有服务 |
| **强制通道纳管** | 每条存活隧道必须调用 `tunnel_register`（或平台 `tunnel_deploy`）登记，并写入 `<taskDir>/shared/tunnels.json` | 搭建“黑户隧道”不登记、不共享，导致后续单兵重复建链或遗忘清理 |

---

## Step 1: 被动网络拓扑盘点

在跳板主机上优先使用只读系统命令收集网络视图，避免触发主动流量：

- **Linux 跳板机**：`ip -br addr`、`ip route show`、`ip neigh show`、`ss -tulnp`、`/etc/resolv.conf`
- **Windows 跳板机**：`ipconfig /all`、`route print`、`arp -a`、`netstat -ano`、`netsh interface portproxy show all`

从上述输出中识别：双网卡/多网段边界、内部网关、内部 DNS 服务器、目标侧已占用的本地端口集合。

---

## Step 2: 通道选型矩阵（单端口转发 vs SOCKS5）

| 能力维度 | 单端口转发（`netsh portproxy` / `ssh -L`） | 动态 SOCKS5 代理（`ssh -D` / SOCKS5 隧道） |
|---|---|---|
| **适用场景** | 仅需访问单一目标的 1–2 个明确服务端口（如 443、445、3389、1433） | 需要访问多个内网主机与多类 TCP 协议（HTTP/LDAP/SMB/WinRM/Kerberos） |
| **权限与依赖** | Windows `netsh portproxy` 需管理员权限，零额外二进制；`ssh -L` 需 SSH 客户端 | 需客户端工具支持 SOCKS5（或 `proxychains`/原生 SOCKS5 参数） |
| **DNS 解析注意** | 直接映射目标 IP:Port，不依赖代理端 DNS | 必须使用远程解析（`socks5h` / SOCKS5 ATYP=DOMAINNAME）或维护明确 `/etc/hosts` 映射 |
| **清理成本** | 必须记录精确 `delete` 命令防止遗留监听规则 | 终止对应代理进程并调用 `tunnel_teardown` 清理 |

---

## Step 3: 冲突预检、规则生成与连通性验证

使用纯标准库脚本 `scripts/pivot_check.py` 执行本地端口占用检查、生成无冲突的 `netsh interface portproxy` 命令（附带校验与清理命令）以及验证 TCP/SOCKS5 链路：

```bash
# 1. 检查本机常用代理端口是否被占用，并推荐 3 个空闲端口
python3 ${SKILL_DIR}/scripts/pivot_check.py port-check \
  --host 127.0.0.1 \
  --ports 1080,1081,8080,8443 \
  --find-free 3

# 2. 生成无冲突的 Windows netsh portproxy 转发命令与清理命令（可传入目标已知占用端口表）
python3 ${SKILL_DIR}/scripts/pivot_check.py netsh-plan \
  --action add \
  --listen-addr 0.0.0.0 \
  --listen-port 18443 \
  --connect-addr 10.10.20.5 \
  --connect-port 443 \
  --used-ports 80,443,3389

# 3. 验证单端口转发 TCP 连通性
python3 ${SKILL_DIR}/scripts/pivot_check.py verify-tcp \
  --host 127.0.0.1 \
  --port 18443

# 4. 验证 SOCKS5 代理握手，并可选验证经代理转发至内网目标的端到端连通性
python3 ${SKILL_DIR}/scripts/pivot_check.py verify-socks5 \
  --proxy-host 127.0.0.1 \
  --proxy-port 1080 \
  --target-host 10.10.20.5 \
  --target-port 445
```

---

## Step 4: 纳管登记与 `shared/tunnels.json` 规范

1. **先查现有隧道**：调用 `tunnel_list` 并检查 `<taskDir>/shared/tunnels.json`，若已存在通向目标网段的健康隧道，先用 `verify-socks5` / `verify-tcp` 验活并直接复用。
2. **平台纳管登记**：新建隧道经连通性验证通过后，立即调用 `tunnel_register` 登记到 ARTEX 平台。
3. **同步共享台账**：将隧道元数据追加写入 `<taskDir>/shared/tunnels.json`，并通过 `record_fact` 写入 `artifact_paths`：
   ```json
   {
     "id": "pivot-hop1-socks5",
     "type": "socks5",
     "listen": "127.0.0.1:1080",
     "via_host": "192.168.10.15",
     "reachable_cidrs": ["10.10.20.0/24"],
     "teardown_cmd": "tunnel_teardown / kill <pid>",
     "verified_at": "2026-01-01T00:00:00Z"
   }
   ```
4. **收尾清理**：任务结束或隧道失效时，按 `teardown_cmd` 清理 `netsh` 规则或调用 `tunnel_teardown` 释放端口。

---

## 交付检查清单 (Definition of Done)

- [ ] 已完成被动网卡/路由/ARP/监听端口采集，明确目标可达网段。
- [ ] 已在绑定前通过 `pivot_check.py port-check` 确认无本地端口冲突。
- [ ] 已通过 `verify-tcp` 或 `verify-socks5` 验证新通道端到端可用。
- [ ] 已调用 `tunnel_register` 纳管并更新 `<taskDir>/shared/tunnels.json`（含清理命令）及 `record_fact(artifact_paths=...)`。
