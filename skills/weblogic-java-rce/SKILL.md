---
name: weblogic-java-rce
description: Java 与 Oracle WebLogic 资产的结构化安全评估纪律：先执行只读版本与端点清单测绘、严禁在应用服务器上运行阻塞式全盘扫描以免引发服务崩溃、强制 XML 实体转义与格式校验、并通过 register_session 与 shared/ 目录规范化沉淀会话与证据。
---

# WebLogic / Java 应用服务器评估纪律（weblogic-java-rce）

Java 应用服务器（尤其是 Oracle WebLogic Server）通常承载核心业务并运行在受限 JVM 堆内存与线程池配额内。本技能规范评估顺序、XML 报文卫生、主机稳定性保护以及 ARTEX 平台会话/产物纳管，避免因粗暴扫描或畸形报文导致误报、服务雪崩或证据丢失。

> 若目标并非 Oracle WebLogic（如 Spring / Tomcat / Netflix Genie / FastAPI / Flask / Next.js / PHP 后台），请优先加载 `web-rce-gadget-playbook` 或 `oss-cms-patch-audit`。

---

## 边界与稳定性纪律（Agent 必读）

| 阶段 | 允许操作 | 严格禁止 |
|---|---|---|
| **端点与版本盘点** | 使用 `scripts/wls_probe.py plan` 生成只读 `HEAD`/`GET` 端点清单，核对 HTTP 响应头、Cookie 命名与版本范围 | 未确认版本与暴露面就直接高并发发包、盲打破坏性请求或重复撞击敏感管理接口 |
| **XML/SOAP 处理** | 发送前通过 `scripts/wls_probe.py validate` 校验良构性、通过 `escape` 处理特殊实体，并正确区分标准 XML 命名空间 | 手拼未转义的 `&`、`<`、`>` 或非法控制字符导致解析异常；在请求中引入未校验的外部 DTD/ENTITY |
| **应用服务器稳定性** | 取得授权诊断上下文后，仅做**有界定点读取**（如 `$DOMAIN_HOME/config/config.xml`、`registry.xml`、受限行数日志） | **严禁在应用服务器执行阻塞式全盘扫描**（如 `find /`、`dir /s`、无边界磁盘 grep 或高并发目录爆破），防止 I/O 耗尽、线程池饿死或 JVM OOM 崩溃 |
| **会话与证据纳管** | 验证稳定通道后立即调用 `register_session` 登记会话，产物统一落盘至 `<taskDir>/shared/weblogic_<host>/` 并附 `artifact_paths` | 在临时目录散落未登记产物、跳过 `register_session` 导致下游单兵无法复用已验证会话 |

---

## 四阶段标准化流程

### Phase 1: 只读版本与端点清单测绘

先建立目标 WebLogic/Java 实例的只读端点清单，核查暴露面与版本特征（如 `X-Powered-By`、`Server`、`ADMINCONSOLESESSION`、`JSESSIONID` 及响应状态码）：

```bash
python3 ${SKILL_DIR}/scripts/wls_probe.py plan \
  --base-url https://target.example.com:7002 \
  --profile standard
```

- 将清单保存至 `<taskDir>/shared/weblogic_<host>/endpoint_plan.json`。
- 根据只读响应确认实际存活端点与 WebLogic 主次版本范围（10.3.6 / 12.1.3 / 12.2.1.x / 14.1.1.x），再决定下一步深入评估策略；对返回 404/不可达的端点及时收敛，不反复重试。

### Phase 2: XML 良构性校验与实体转义

处理任何 XML / SOAP 配置模板或服务端响应样本时，必须使用确定性工具校验与转义：

```bash
# 1. 对文本或属性值执行确定性 XML 实体转义（自动检测非法 XML 1.0 控制字符）
python3 ${SKILL_DIR}/scripts/wls_probe.py escape \
  --text 'AdminServer & NodeManager <prod> "v12"' \
  --mode attr

# 2. 校验 XML 文档良构性、提取命名空间并检测危险 DTD/ENTITY 声明
python3 ${SKILL_DIR}/scripts/wls_probe.py validate \
  --file /path/to/sample_soap.xml
```

- 注意：SOAP/XML 常见的标准命名空间 URI（如 `www.w3.org`、`schemas.xmlsoap.org`、`www.bea.com`）仅作协议声明用途，不属于业务外联资产，切勿误录入 `insert_assets` 或任务范围。

### Phase 3: 有界应用上下文核查（严禁全盘扫描）

在获得合法访问上下文后，**严格禁止全盘遍历**，仅读取与评估直接相关的定界路径：

- **WebLogic 关键定位文件**（按需单文件读取）：
  - `$MW_HOME/registry.xml`（安装组件与精确补丁版本）
  - `$DOMAIN_HOME/config/config.xml`（域拓扑、监听端口、受管节点配置）
  - 进程命令行参数（`ps -ef | grep java` 或 `wmic process where "name='java.exe'" get ProcessId,CommandLine`）确认 `-Dweblogic.Name`、`-Ddomain.home` 与 JDK 版本。
- **日志读取必须限流**：仅使用 `tail -n 100` 或按关键字精准检索，禁止 `cat` 数百 MB 的 `AdminServer.log`。

### Phase 4: 会话纳管与共享目录沉淀

1. **会话纳管**：若建立了可复用的诊断/交互通道，立即调用 ARTEX `register_session` 登记会话，并通过 `session_recon` 验证通道活性。
2. **共享产物落盘**：将端点盘点清单、脱敏配置摘要、版本核验证据写入 `<taskDir>/shared/weblogic_<host>/`。
3. **事实与漏洞回写**：调用 `record_fact` 时在 `artifact_paths` 中填入共享目录绝对路径；确认真实风险且具备可复现只读/低影响证据后，再规范化调用 `report_finding`。

---

## 交付检查清单 (Definition of Done)

- [ ] 已生成并审阅只读端点清单，记录 WebLogic/JDK 版本与暴露面状态。
- [ ] 全程未在目标应用服务器执行阻塞式全盘扫描或高并发压测。
- [ ] 所有 XML 模板/样本均已通过 `wls_probe.py` 校验与转义。
- [ ] 已按需调用 `register_session` 纳管通道，并将产物归档至 `<taskDir>/shared/weblogic_<host>/` 且附带 `artifact_paths`。
