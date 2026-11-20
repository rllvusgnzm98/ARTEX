---
name: lazy-chunk-downloader
description: 从本地 webpack 或 Vite 运行时重建懒加载 JS/CSS chunk 文件名，并按 base URL 下载。适用于补齐代码分割 bundle 后再做接口侦察。先 dry-run 看 publicPath，再下载。只访问已授权目标。
---

# 懒加载 chunk 下载

从已经落在本地的 JavaScript bundle 里，重建 webpack / Vite 运行时才会拼出来的懒加载 chunk 文件名，再按 base URL 下载。它重建的是运行时的 chunk 文件名映射，不是站点爬虫。

只下载已授权目标。404 很常见：哈希表里会有这次构建没发出的 id。失败记一笔后继续，不要把整批当成失败。

除 Node 18+ 自带的 `fetch` 外，脚本只用内置的 `fs` 和 `path`，没有第三方包。

## 它怎么拼文件名

- **webpack 5**：`__webpack_require__.u(chunkId)` 拼 JS，`.miniCssF` 拼 CSS。脚本解析字符串字面量、chunkId 和 hash/name 映射，并对每个 chunkId 展开。`__webpack_require__.p` 的 publicPath 会打印出来。
- **Vite**：`__vite__mapDeps([...])` 里的动态 import 路径。
- **兜底**：引号里写死的 `*.js`、`*.chunk.js`、`*.css`。这也覆盖 Next.js `_buildManifest.js` 的路由到 chunk 列表，包括以 `_` 开头的 `_error`、`_app`，以及 `[accountId]`、`[[...brandSlug]]` 这种带方括号的动态段。

`--dir` 既是扫描目录，也是落盘根目录：相对路径会接到 `--dir` 下面。扫描时会跳过 `node_modules` 和 `.git`。

## 步骤

1. 先 dry-run，确认 publicPath，再下载。没有 base URL 时这条只列出文件名，不访问网络：

```bash
node ${SKILL_DIR}/scripts/fetch_lazy_chunks.js --dir <dir> --dry-run
```

已经知道站点或资源 base 时，把 URL 放在 `--dir` 前面，仍然先加 `--dry-run`：

```bash
node ${SKILL_DIR}/scripts/fetch_lazy_chunks.js <baseURL> --dir <dir> --dry-run
```

每一行是一个 chunk 路径。脚本会打印数量和检测到的 publicPath。

2. 确定 base URL。chunk 路径是相对的。dry-run 若给出 `/app/` 或绝对 CDN，真实地址是 `<origin><publicPath><chunkname>`。把已经包含该前缀的 base 传进去，或把 base 直接指到 CDN 的 origin。用户没给 base 就先问，不要猜 CDN。

3. 去掉 `--dry-run` 再下载。只要 JS 时加 `--ext js`：

```bash
node ${SKILL_DIR}/scripts/fetch_lazy_chunks.js https://example.com/ --dir <dir>
node ${SKILL_DIR}/scripts/fetch_lazy_chunks.js https://example.com/ --dir <dir> --ext js
```

每一行是 `ok` 或 `FAIL`。`FAIL ... HTTP 404` 不是致命错误。

生产环境按 Linux 上的 `node` 调用。Windows 同一条命令可用，路径按本机写。

重建若漏了 chunk，可以先用 `js-beautify` 展开运行时再扫一次。解析器能处理单行压缩代码，极端变体才需要这一步。

## 检查项

- [ ] dry-run 看到的 publicPath 已经体现在实际 base URL 里
- [ ] 汇报 chunk 数量、publicPath、ok/FAIL 计数和落盘目录
- [ ] 新 chunk 交给 `js-endpoint-extraction` 或 `jshero`，不在这里做端点分类
