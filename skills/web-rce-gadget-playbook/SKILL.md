---
name: web-rce-gadget-playbook
description: 当在 PHP、Python、Node.js 或 Java Web 应用中发现任意文件写、路径穿越、硬编码密钥、松散比较认证绕过、SSTI 或反序列化特征时加载：提供非破坏性原语升级路径与只读会话/JWT/序列化结构解析工具。
---

# Web 原语升级与令牌/反序列化结构审计（web-rce-gadget-playbook）

适用于 Python（Flask/FastAPI/Django）、Node.js（Next.js/Express）、PHP（Cacti/Dolibarr/CMS）与 Java（Spring/Tomcat/Genie）应用。核心原则：**拿到局部原语（文件写、配置读取、密钥泄漏、序列化特征）后，先用离线只读检查确认数据结构与验证边界，再按最小影响路径完成安全边界实锤。**

## 常见原语升级决策矩阵

1. **任意文件写 / 路径穿越写文件**：
   - 先核查目标运行时栈与进程触发方式：
     - **Java/C 子进程触发** → 评估环境变量 `LD_PRELOAD` 与可控共享库路径；
     - **PHP/Apache** → `.htaccess` / PHP-FPM 配置或模板缓存位；
     - **Node.js / Next.js** → 动态加载配置或模块路由覆写（注意避免破坏生产常驻服务）。
   - 若需要删除/清理文件验证权限边界（如 DoS 类条件），先确认目标应用在缺失该文件时是进入受控异常态还是跳转安装向导。
2. **硬编码密钥 / 弱认证 / 会话伪造**：
   - 发现 JWT、Flask session cookie（`eyJ...`）或 PHP 序列化串时，先运行只读解析脚本查看载荷结构与签名算法：
     ```bash
     python3 ${SKILL_DIR}/scripts/auth_token_inspect.py --mode jwt "<token>"
     python3 ${SKILL_DIR}/scripts/auth_token_inspect.py --mode flask "<session_cookie>"
     ```
   - 遇到旧版 PHP `md5()`/`sha1()` 弱类型比较 `==`（非 `===`）时，优先排查已知 `0e` 前缀校验点。
3. **SSTI 与反序列化**：
   - SSTI 必须先用 `{{7*7}}` / `${7*7}` 区分服务端模板执行与前端 CSTI；
   - 反序列化先识别编码魔数（Java `rO0`、PHP `O:<len>:...`、Python pickle `\x80\x03`/`\x80\x04`）与白名单校验，优先以无害只读回显或 `oob_allocate` 验证可达性。
