---
name: ad-exchange-relay
description: 内网 Active Directory 与 Exchange 暴露面只读分诊清单：执行域查询前先核验工作组与域成员身份，只读检查 SMB/LDAP 签名姿态、TLS 证书与 Exchange HTTP 版本响应头，并核查经 SOCKS5 代理访问时的 Kerberos 时钟偏差与 DNS 解析就绪状态。
---

# 内网 AD / Exchange 暴露面只读分诊规范（ad-exchange-relay）

在内网评估中，直接对未确认身份的主机执行域枚举、或在存在时钟偏差/DNS 断裂的 SOCKS5 链路上盲试 Kerberos 认证，会产生大量无效错误。本技能提供严谨的三阶段只读分诊流程，帮助快速识别域拓扑、协议签名配置缺陷（SMB/LDAP/TLS）与 Exchange 版本信息。

---

## 边界与只读分诊纪律（Agent 必读）

| 维度 | 允许与推荐做法 | 严格禁止 |
|---|---|---|
| **域成员前置核验** | 执行任何域查询前，先用只读主机命令核实目标处于工作组还是 AD 域 | 在独立工作组主机上盲跑域控查询或 LDAP/Kerberos 工具 |
| **协议签名与响应头只读审计** | 使用 `scripts/ad_surface_check.py` 执行无认证只读 TCP Banner、TLS 证书、HTTP 响应头与 SMBv2 Negotiate 签名标志位检查 | 未获明确授权发起强制认证、中间人流量劫持、凭据爆破或破坏性写入操作 |
| **SOCKS5 下 Kerberos/DNS 校验** | 提前核验本机与目标/域控的时钟偏差（Kerberos 默认容忍 <= 300 秒）以及 FQDN DNS 解析路径 | 使用裸 IP 发起 Kerberos SPN 请求，或忽视时钟偏差（`KRB_AP_ERR_SKEW`）反复重试导致账号锁定风险 |

---

## 三阶段分诊工作流

### Phase 1: 工作组 vs 域成员核验

若已具备主机只读上下文，先执行轻量级只读命令确认域归属（工作组主机直接跳过后续域查询）：

- **域/工作组判定**：
  - `systeminfo | findstr /B /C:"Host Name" /C:"OS Name" /C:"Domain"`
  - `nltest /dsgetdc:<domain>`（确认域控 FQDN 与站点信息）
  - `whoami /fqdn`（仅域账户成功返回 DN；本地工作组账户直接报错即表明非域上下文）
  - `ipconfig /all`（核对 Primary DNS Suffix 与内部 DNS 服务器地址）

### Phase 2: 只读协议、证书与 Exchange 响应头核查

使用纯标准库只读探测脚本 `scripts/ad_surface_check.py`（支持原生直连或经由已登记的 SOCKS5 隧道探测），一次性输出结构化 JSON 评估清单：

```bash
# 1. 生成离线检查计划（不建立网络连接）
python3 ${SKILL_DIR}/scripts/ad_surface_check.py \
  --host mail.corp.local \
  --ports 80,88,389,443,445,636 \
  --dry-run

# 2. 经由 SOCKS5 隧道执行只读 AD/Exchange 表面核查（TCP / TLS 证书 / HTTP 头 / SMBv2 签名姿态）
python3 ${SKILL_DIR}/scripts/ad_surface_check.py \
  --host 10.10.20.10 \
  --sni mail.corp.local \
  --ports 80,88,389,443,445,636,3268,3269 \
  --socks5 127.0.0.1:1080 \
  --http-paths /,/owa/auth/logon.aspx,/ecp/,/ews/
```

**重点判读字段**：
- **SMB 签名姿态（445）**：观察 `smb_signing.signing_enabled` 与 `smb_signing.signing_required`；若 `signing_required` 为 `false`，记录为 SMB 签名未强制配置缺陷。
- **LDAP / LDAPS 姿态（389 / 636 / 3268 / 3269）**：核对 389 明文端口与 636/3269 LDAPS TLS 端口可达性，检查证书主题（CN/SAN）、签发 CA（是否部署企业内部 AD CS）与有效期。
- **Exchange HTTP/HTTPS 表面（80 / 443）**：核对 `X-OWA-Version`、`X-FEServer`、`X-BEServer`、`Server`、`WWW-Authenticate`（认证方案列表如 `Negotiate`、`NTLM`、`Basic`）及重定向路径，据此对照版本基线与补丁级别。

### Phase 3: SOCKS5 下的 Kerberos 时钟偏差与 DNS 检查

1. **时钟偏差核对**：审阅 `ad_surface_check.py` 输出的 `clock_skew_seconds`（来自 HTTP `Date` 响应头与 SMBv2 Negotiate `SystemTime` 字段）。若 `abs(clock_skew_seconds) > 240`（逼近 Kerberos 300 秒阈值），在继续任何 Kerberos 认证前必须先同步本地时间或调整工具时钟偏移。
2. **DNS 与 FQDN 校验**：标准 SOCKS5（TCP CONNECT）不转发常规 UDP/53 DNS 查询。经由 SOCKS5 访问 AD/Exchange 时：
   - 优先确认 TCP DNS 可用或将域控/Exchange 的准确 FQDN 与 IP 写入本机解析配置；
   - 核对 TLS 证书 SAN 与 `nltest` 输出的规范 FQDN，避免因短名或 IP 触发 SPN 不匹配。
3. **证据落盘与登记**：将核查 JSON 保存至 `<taskDir>/shared/ad_surface_<host>.json`，调用 `record_fact` 写入关键配置结论并附带 `artifact_paths`；确认存在安全配置缺陷（如未强制 SMB 签名、过时 Exchange 版本或明文暴露）时规范化调用 `report_finding`。

---

## 交付检查清单 (Definition of Done)

- [ ] 已确认目标是域成员还是独立工作组，未对工作组主机执行无效域查询。
- [ ] 已完成只读 TCP/TLS/HTTP/SMBv2 签名姿态核查，并将 JSON 清单归档至 `<taskDir>/shared/`。
- [ ] 已核对 `clock_skew_seconds` 与 DNS/FQDN 解析就绪状态，满足 SOCKS5 下的 Kerberos 约束。
- [ ] 已通过 `record_fact` 登记结构化结论与 `artifact_paths`。
