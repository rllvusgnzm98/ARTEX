# TBHM Application Analysis — 技术参考手册

本手册收录 Jason Haddix TBHM 2026 Core 课程中框架安全备忘单（Framework Security Cheat Sheet）的核心技术参考。

---

## 1. SSTI 万能探针与引擎确认表

- **万能探测 Polyglot**：`${{<%[%'"}}%\`
- **确认逻辑表**：
  | 测试 Payload | 预期结果为 49 的引擎 | 进一步区分测试 | 关键确认特征 |
  |---|---|---|---|
  | `{{7*7}}` | Jinja2 (Python), Twig (PHP), Nunjucks (JS) | `{{7*'7'}}` | Jinja2 返回 `7777777`；Twig 返回 `49` |
  | `${7*7}` | FreeMarker, Velocity, Spring SpEL | `${T(java.lang.Runtime)}` | Java 核心栈模板解析 |
  | `<%= 7*7 %>` | ERB (Ruby), EJS (Node.js) | `<%= process.version %>` | 脚本式模板引擎 |
  | `#{7*7}` | Pug / Jade (Node.js), Slim (Ruby) | `#{process.mainModule}` | 缩进式模板引擎 |
  | `{7*7}` | Smarty (PHP) | `{php}echo 1;{/php}` | 老版本 PHP Smarty 模板 |

---

## 2. 反序列化格式特征识别

| 格式 / 语言 | 魔术头字节 (Magic Bytes) | 典型网络特征 | 常见产生位置 |
|---|---|---|---|
| **Java ObjectOutputStream** | `AC ED 00 05` (Hex) | Base64: `rO0AB...` | Cookie, ViewState, RMI 接口, JSESSIONID |
| **.NET BinaryFormatter** | `00 01 00 00 00 FF FF FF FF` | Base64: `AAEAAAD/////` | `__VIEWSTATE` (MAC关闭时), 自定义反序列化接口 |
| **PHP serialize()** | `O:{length}:"{class}":...` | 明文 ASCII 字符串 | Cookie, Session 数据, 参数传递 |
| **Python Pickle** | `\x80\x04` 或 `\x80\x03` | Base64: `gAR...` 或 `gAN...` | Django/Flask Pickle Session, 消息队列 |
| **Python Unsafe YAML** | `!!python/object:` | 明文 YAML 配置文件 | YAML 上传或反序列化解析接口 |

---

## 3. 常见默认高危调试与管理端点

| 分类 | 典型端点路径 | 危害说明 |
|---|---|---|
| **Actuator (Spring Boot)** | `/actuator/env`, `/actuator/heapdump`, `/actuator/jolokia` | 泄露全部环境变量、数据库明文凭证、JVM堆内存 |
| **Go 调试工具** | `/debug/pprof/`, `/debug/pprof/goroutine` | 导出协程堆栈与内存快照 |
| **Symfony 性能分析器** | `/_profiler/`, `/_profiler/empty/search/results` | 记录全部请求历史、SQL 语句与 Session 信息 |
| **Laravel 调试工具** | `/telescope`, `/_debugbar/assets/stylesheets` | 生产环境未关闭调试工具，造成全站敏感信息泄露 |
| **Django 调试栏** | `/__debug__/` | 泄露历史 SQL 查询与模板变量 |
| **Swagger / OpenAPI** | `/swagger-ui.html`, `/openapi.json`, `/v3/api-docs` | 暴露未公开后端 API 端点与请求参数结构 |

---

## 4. 文件上传关键安全检查项 (40+ 维度提要)

1. **Blind SSRF**：在 multipart 表单的 `filename` 字段中测试 SSRF 回连。
2. **文件名双扩展名 / 空字节**：`shell.php.jpg`、`shell.php%00.jpg`。
3. **MIME 类型混淆**：修改 `Content-Type` 为 `image/jpeg`，但上传脚本内容。
4. **图片元数据 Exif 注入**：利用 `exiftool` 在 Comment 或 Caption 中嵌入脚本。
5. **Zip Slip (压缩包解压穿透)**：上传包含 `../../` 相对路径的恶意 Zip 包。
6. **SVG 脚本执行**：上传包含 `<script>` 标签的 SVG 矢量图导致跨站脚本 (XSS)。
7. **覆盖关键配置文件**：在支持任意路径写入时尝试覆盖 `.htaccess` 或 `web.config`。
8. **解析器差异 (Right-To-Left Override)**：利用 Unicode 控制字符反转扩展名显示（如 `name.%E2%80%AEphp.jpg`）。
