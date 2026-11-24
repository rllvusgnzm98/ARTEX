# ScopeSentry 故障排查

| 现象 | 处理 |
| --- | --- |
| MCP 无工具 | 检查 URL、API Key、ScopeSentry 是否运行 |
| 401 / 403 | 重新创建或更换 API Key |
| 资产查不到 | 确认 `filter.project` 为 ObjectID；勿在 search 写 project |
| 模板/任务创建失败 | `template` 必须是模板 ObjectID；`node` 填在线节点名 |
| 查询很慢/卡住 | 有项目时加 `filter.project`；search 对已索引字段改用 `==` 或 `^` 前缀，少用 `=`；缩小 `pageSize` |
