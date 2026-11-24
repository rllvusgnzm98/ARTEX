# ScopeSentry 资产查询语法（`list_assets` / `count_assets`）

`count_assets` 与 `list_assets` 使用相同的 `asset_type`、`search`、`filter`，返回 `{ "total": N }`，对应 Web 端 `/api/assets/common/total`。

```json
{
  "asset_type": "subdomain",
  "search": "task==\"某任务名\"",
  "filter": {"project": ["<项目ObjectID>"]}
}
```

**性能建议（`list_assets` / `count_assets` 通用）：** 有项目条件时优先用 `filter.project` 缩小范围；`search` 中对已建索引字段尽量用 `==` 全等或 `^` 前缀匹配（见 §3），避免大面积 `=` 模糊查询拖慢响应。无项目上下文时不强制加项目筛选。

## 1. 资产类型 `asset_type`

`asset`、`RootDomain`、`subdomain`、`app`、`mp`、`UrlScan`、`SensitiveResult`、`DirScanResult`、`crawler`、`vulnerability`、`PageMonitoring`、`IPAsset`、`SubdomainTakerResult`

别名示例：`web`→asset、`vuln`→vulnerability、`ip`→IPAsset、`url`→UrlScan

## 2. 参数说明

| 参数 | 说明 |
| --- | --- |
| `pageIndex` / `pageSize` | 分页，默认 1 / 20 |
| `search` | 搜索表达式（见 §3） |
| `filter` | 精确过滤 JSON（见 §4） |
| `sort` | 仅 UrlScan、DirScanResult 支持按 `length` 排序 |
| `sid` | 仅 SensitiveResult：敏感规则名称 |

`search` 与 `filter` **可同时使用**。

## 3. search 搜索表达式

自定义 DSL（**不是 SQL**）：

| 运算符 | 含义 | 索引 | 示例 |
| ---- | ---- | ---- | ---- |
| `=` | 模糊匹配（regex） | 不走索引 | `domain=example` |
| `==` | 精确匹配（全等） | **走索引** | `port==443` |
| `!=` | 排除 | — | `port!="80"` |
| `&&` | 与 | — | `domain==example.com && port==443` |
| `||` | 或 | — | `title=admin \|\| body=login` |

**索引与运算符：** `domain`、`ip`、`port`、`title` 等字段已建索引，但仅 **`==` 全等** 或 **值以 `^` 开头的前缀匹配**（如 `domain=^example.com`）能走索引；**`=` 会转为 regex 模糊匹配，无法使用索引**，数据量大时易变慢。

**所有类型通用 search 字段：** `tag`、`task`（任务名称）、`rootDomain`

**project 不能写在 search 里**（无效或与 `&&` 组合时报错）。筛项目请用 `filter.project`。

**各类型常用 search 字段：**

| asset_type | 字段 |
| --- | --- |
| asset | domain, ip, port, service, app, title, statuscode, icon, banner, type, body, header |
| RootDomain | domain, icp, company |
| subdomain | domain, ip, type, value |
| app | name, icp, company, category, description, url, apk |
| mp | name, icp, company, category, description, url |
| UrlScan | url, input, source, resultId, type |
| SensitiveResult | url, sname, body, info, md5 |
| DirScanResult | url, statuscode, redirect, length |
| vulnerability | url, vulname, matched, request, response, level |
| crawler | url, method, body, resultId |
| PageMonitoring | url, hash, diff, response |
| IPAsset | ip, domain, port, service, webServer, app |
| SubdomainTakerResult | domain, value, type, response |

**search 示例：**

- `domain==www.example.com && port==443`（全等，走索引）
- `domain=^example.com`（前缀匹配，走索引）
- `ip==192.168.1.1`
- `task=="某任务名"`
- `level==high`（vulnerability）
- `statuscode==200`（DirScanResult）

需模糊包含时再用 `=`，如 `title=admin`（不走索引，宜配合项目等条件缩小范围）。

## 4. filter 精确过滤

JSON 对象：同 key 多个值为 **OR**，不同 key 为 **AND**。

**有项目条件时优先用 `project`：** 若用户或上下文已明确项目，且 asset_type 支持 `project`，应带上以缩小范围；无项目信息时不强制。

| filter key | 含义 | 取值说明 |
| --- | --- | --- |
| `project` | 所属项目 | **ObjectID**，用 `list_projects` / `list_projects_data` 获取 |
| `task` | 来源任务 | **任务名称**，用 `list_tasks` 的 `name` |
| `port` | 端口 | 如 `"443"` |
| `service` | 服务/协议 | 如 `"https"` |
| `app` | 应用指纹 | 如 `"Nginx"` |
| `icon` | 图标 hash | |
| `statuscode` | HTTP 状态码 | 主要用于 asset |
| `status` | 状态 | UrlScan/DirScan HTTP 码；漏洞/敏感信息处理状态 |
| `level` | 漏洞等级 | critical / high / medium / low / info |
| `type` | 类型 | 如子域名记录类型 A、CNAME |
| `color` | 敏感规则颜色 | SensitiveResult |
| `sname` | 敏感规则名 | SensitiveResult |
| `tags` | 标签 | |

**各类型可用 filter key：**

| asset_type | filter key |
| --- | --- |
| asset | project, port, service, app, icon, statuscode, type, task, tags |
| RootDomain | project, tags |
| subdomain | project, type, task, tags |
| app / mp | project, tags |
| UrlScan | status, tags |
| DirScanResult | status, tags |
| SensitiveResult | status, color, sname, tags |
| crawler | project, task, tags |
| vulnerability | project, level, status, task, tags |
| PageMonitoring / SubdomainTakerResult | tags |
| IPAsset | project, port, service, app |

**filter 示例：**

```json
{"project": ["<项目ObjectID>"], "port": ["443"]}
```

**组合查询示例：**

```json
{
  "asset_type": "asset",
  "search": "domain=^baidu && port==443",
  "filter": {"project": ["<项目ObjectID>"]},
  "pageIndex": 1,
  "pageSize": 10
}
```

**注意：**

- 有项目条件时优先带 `filter.project`（支持时）；无项目上下文可不强制
- `filter.project` 勿填项目显示名称
- 已知值用 `==`，前缀用 `^`；避免对大表滥用 `=` 模糊匹配
- UrlScan 的 HTTP 状态用 `filter.status`；DirScanResult 可在 search 中用 `statuscode==200`
- SensitiveResult 按规则名：`search` 用 `sname=规则名`，或 `filter.sname`

## 5. 排序 sort

仅 **UrlScan**、**DirScanResult** 支持：

```json
{"length": "ascending"}
```

其他类型忽略 `sort`，按时间默认排序。
