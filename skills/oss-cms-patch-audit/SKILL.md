---
name: oss-cms-patch-audit
description: 当目标运行开源 CMS、框架或插件（WordPress、PrestaShop、Dolibarr、SuiteCRM、Cacti、FastAPI/Flask/Next.js 等），且存在本地源码、公开仓库或补丁差异可供白盒辅助定位时必须加载：快速盘点未鉴权入口、权限回调缺失、高危 Sink 与版本补丁差异。
---

# OSS / CMS 白盒源码与补丁差分审计（oss-cms-patch-audit）

面向漏洞赏金、开源 N-day 复核与白盒辅助黑盒验证。核心目标：**30 秒内用静态脚本把“路由入口 + 鉴权缺失 + 危险汇聚点 + 补丁变更”结构化拉出来，避免手写脆弱 `grep`/`sed` 循环或盲猜 CVE 编号。**

## 标准化工作流

1. **版本与真实路径锚定**：先核实目标实际运行的插件 slug、版本号或文件存在性，再拉取对应源码；不凭猜测硬套 CVE。
2. **静态入口与高危 Sink 扫描**：
   ```bash
   python3 ${SKILL_DIR}/scripts/oss_sink_scan.py /path/to/source_dir --limit 80
   ```
   - 自动识别 PHP（WordPress `wp_ajax_nopriv_*`、`register_rest_route`、`permission_callback`、PrestaShop `ModuleFrontController`、`unserialize`/`file_put_contents`）、Python（FastAPI/Flask 路由、`yaml.load`/`pickle`/`eval`）、JS/TS（Express/Next.js API 路由、`writeFileSync`/`exec`）与 Java（Spring Mapping、`ObjectInputStream`/`Runtime.exec`）。
3. **补丁差分定位（已知存在修复版本时）**：
   ```bash
   git -C /path/to/repo diff v_vuln..v_fixed > patch.diff
   python3 ${SKILL_DIR}/scripts/patch_diff_triage.py patch.diff
   ```
   - 直接提取被修改的路由/控制器文件、新增的权限校验（`current_user_can`/`nonce`/sanitizer）与路径规范化差异。
4. **运行时验证原则**：静态库结构（如静态 `db.sql` 或默认配置）往往与线上容器/生产实例存在偏差，构造请求前务必对目标实测确认入口与状态。
