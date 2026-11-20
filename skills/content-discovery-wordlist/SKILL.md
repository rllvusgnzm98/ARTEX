---
name: content-discovery-wordlist
description: 为目标生成定制内容发现词表。结合技术栈公开资料与可选的 JS 路径种子，去重后写入当前目录 custom_list.txt，供 ffuf 等路径发现工具使用。在要自定义 wordlist、fuzz 列表或从 JS 提取路径时使用。
---

# 内容发现词表

只生成词表，不发起扫描。产出是当前目录的 `custom_list.txt`。用哪一个路径发现工具由使用者另选，本技能不绑定仓库里没有的扫描器。

目标是一份针对该站点的列表，而不是把公开大词表再抄一遍。onelistforallmicro 和 raft-large 已经覆盖了常见路径，下面两阶段要补的是它们没有的部分。

## 步骤 1 — 收集输入

先把能拿到的材料收齐，再开始检索。顺序如下。

**技术栈。** 从用户给出的参数、对话里已有的爬虫输出、响应头、招聘信息或报错栈里整理。记下框架、语言、数据库、云厂商、CDN、第三方应用。没有这些信息就先查，不要空着手编一份泛化列表。

**JS 文件（可选，但价值高）。** 用户若提供了 bundle、source map 或已经提取出的 JS：

- 抽出 URL 形态的字符串、路由定义、API 路径模式和端点引用
- 这些是应用真实用过的路径，作为最高优先级种子
- 放进 `js-extracted` 桶，最后并进总表时再去重

技术栈和 JS 都没有时，自己把技术栈补齐再进入阶段 1。

## 阶段 1 — 通用发现（第 1–5 轮）

研究**任何** Web 目标都可能出现的路径。目标是深度和冷门变体。

例子只是起点，每轮都要继续补自己的发现。

**管理入口，分成两类：**

- 框架或服务器自带：`/admin`、`/administrator`、`/rails/info`、`/horizon`、`/telescope`、`/django-admin`、`/phpmyadmin`、`/adminer`、`/struts/webconsole`、`/manager/html`、`/solr/admin`。随服务器和框架变化。
- 业务自建：`/portal`、`/management`、`/console`、`/control`、`/backoffice`、`/staff`、`/internal`、`/secure`、`/ops`、`/support`。对照公开漏洞报告里真实出现过的面板路径。

**通用配置与备份：**

`.env`、`.env.local`、`.env.production`、`web.config`、`.htaccess`、`.htpasswd`、`config.json`、`config.yml`、`settings.py`、`application.properties`、`secrets.yml`、`credentials.json`、`database.yml`、`.aws/credentials`，以及备份后缀（`.bak`、`.old`、`.backup`、`.orig`、`.copy`、`~`、`_backup`）和轮转名（`config.1` 等）。

**暴露的开发残留：**

`.git/`、`.git/config`、`.svn/entries`、`.hg/`、`Makefile`、`Dockerfile`、`docker-compose.yml`、`.github/workflows/`、`Jenkinsfile`、`.travis.yml`、`.circleci/config.yml`、`package-lock.json`、`composer.lock`、`yarn.lock`、`Gemfile.lock`、`.DS_Store`、`Thumbs.db`。

**通用 API 形态：**

`/api/v1/`、`/api/v2/`、`/api/v3/`、`/graphql`、`/graphiql`、`/rest/`、`/ws/`、`/wss/`、`/swagger`、`/swagger-ui`、`/swagger.json`、`/openapi`、`/openapi.json`、`/redoc`、`/v1/`、`/v2/`、`/health`、`/healthz`、`/status`、`/metrics`、`/actuator`、`/debug`。

每一轮只钻一个类别。查公开文档、冷门变体，以及公开词表里没有、但写进过漏洞报告的路径。

## 阶段 2 — 技术栈专项（第 6–15 轮）

按已经识别出的技术栈逐项查。每一轮换一个角度。用检索补训练数据里没有的路径，不要只凭记忆。

**该应用自己的配置、备份和残留。** 每种框架的配置文件名、默认安装路径、调试路由、已知暴露文件都不一样。Rails 和 Laravel 不要写成同一份。

**框架和服务器的管理界面。** 查随该技术一起部署的管理、监控入口，例如 sidekiq-web、Resque、Kibana、Grafana、Prometheus、Flower、ActiveAdmin、Forest Admin。

**CVE 里披露过的路径。** 对栈里的每个组件，查 NVD、Exploit-DB、厂商公告和 GitHub 上的 PoC 仓库，只要其中出现过的 URL 路径。放进词表的是路径本身，不是利用步骤。检索式例如：`site:nvd.nist.gov [framework] path disclosure`，`[technology] CVE endpoint exposed`。

**公开漏洞报告。** 从 HackerOne 已披露报告、Bugcrowd、安全博客和 writeup 里摘出探测过或发现过的路径。检索式例如：`site:hackerone.com/reports "[framework]"`，`"[technology] bug bounty" hidden endpoint`，`[framework] security writeup path`。

**边角。** 预发和开发残留、CI 路径、可通过 SSRF 触达的云元数据端点、厂商内部面板、从 APK 里抽出的移动端 API、针对该栈的会议演讲里出现过的路径。凡是公开大词表里不会有的，都归这里。

每轮结束用一句话记下增量：`Round N complete — +X paths (Y unique total). Next: [topic]`。

## 步骤 3 — 汇总

1. 合并 `js-extracted`、阶段 1 和阶段 2。
2. 去重。忽略大小写，保留小写形式。
3. 清理。不要注释，不要空行，一行一条路径。
4. 按字母排序。
5. 写到当前目录的 `custom_list.txt`。

Linux 上：

```bash
sort -u custom_list.unsorted.txt > custom_list.txt
```

把合并后的路径先放进 `custom_list.unsorted.txt`，再排序去重。Windows 上把同一份列表写成当前目录的 `custom_list.txt`（UTF-8、一行一条）即可。

6. 打印摘要：

```
=== Custom Discovery Wordlist Complete ===
Target Stack:     [technologies]
JS Files Seeded:  [N paths extracted] (or "none provided")
Phase 1 Generic:  +NNN paths (Rounds 1-5)
Phase 2 Specific: +NNN paths (Rounds 6-15)
─────────────────────────────────────────
Total Unique:     NNNN paths
Output:           [full path]/custom_list.txt
```

## 完成标准

保存前看这份列表：公开大词表之外是否真有该栈才有的路径。若只是 raft-large 再加几条，就回到阶段 2 继续。价值在阶段 2 的深度和 JS 种子，不在把通用路径再列一遍。
