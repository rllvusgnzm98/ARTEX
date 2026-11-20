---
name: js-endpoint-extraction
description: 从本地 JavaScript 提取 API 路径、绝对 URL 与 fetch/AJAX 目标，供已授权侦察。适用于在 JS 中找隐藏接口，并标出 SSRF、IDOR、开放重定向候选。只读本地文件，不发网络请求。需要 AST 与路由分类时使用 jshero。
---

# JavaScript 端点提取

只处理已经在本地的 `.js`。不下载、不发请求。优先用 Python 脚本（标准库，Linux 与 Windows 都能跑）。同目录的 shell 脚本依赖 perl，Windows 上通常没有，不要当默认路径。

需要更完整的 AST、路由分类、账本去重或敏感信息扫描时，改用 `jshero`。不要在这里再写一套采集器。

## 边界

| 范围 | 允许 | 禁止 |
|---|---|---|
| 输入 | 单个文件、多个文件或一个目录。无参数时递归当前目录全部 `.js` | 联网抓取；代替 `lazy-chunk-downloader` 去下 chunk |
| 输出 | 去重后的路径与 URL，以及分类后的线索 | 把 CSS、字体、图片当成接口；把第三方主机算进范围内 API |

## 步骤

1. 提取。把目录或文件交给脚本，结果在标准输出：

```bash
python3 ${SKILL_DIR}/scripts/extract_endpoints.py
python3 ${SKILL_DIR}/scripts/extract_endpoints.py app.bundle.js
python3 ${SKILL_DIR}/scripts/extract_endpoints.py ./static/js
```

把最终去重列表存到当前工作目录的 `all_endpoints.txt`。

Linux 上若已经有 perl，可以改跑下面这条，参数相同。Windows 不要用它：

```bash
${SKILL_DIR}/scripts/extract_endpoints.sh ./static/js
```

Windows 上若没有 `python3` 命令，用 `python` 调用同一个 `.py`。

2. 分类。把输出分成四组：

- `/api/...` 路由
- 绝对 URL（SSRF、开放重定向候选）
- `.get` / `.post` / `.ajax` / `.load` / `fetch` 的调用目标
- 带 id 或 token 的路径（IDOR 候选）。记下 `?id=`、`?url=`、`?redirect=`

3. 去噪。丢掉 `.css`、`.png`、`.woff`、`.svg` 等静态资源，以及明显的第三方主机。只保留范围内 API。

4. 补全。相对路径要拼上该 JS 的源站。有 `.js.map` 就一起看，原始源里的路由往往更多。找 `API_BASE`、`baseURL` 一类常量，把相对路径还原成完整端点。

单行压缩 bundle 可以先用 `js-beautify` 展开。没有该命令就直接跑 Python 脚本，不要为了美化去装新工具链。

## 检查项

- [ ] 只读了本地文件，没有为了补全去请求目标
- [ ] `all_endpoints.txt` 在当前工作目录，且已去重
- [ ] SSRF / IDOR / 开放重定向候选单独列出
- [ ] 静态资源和第三方主机已滤掉
