# chains-database L3 决策骨架（蒸馏自 reverse-skill database-security/SKILL.md；仅限安全验证）
- 场景:目标工作授权门禁|判据:明确 auth.status=granted，资产/表面/活动均在范围内，且有合法 network_profile 或明确授权的离线样本；若拟执行仓库脚本，须先披露准确命令及副作用并取得用户单独明确同意|转向:任一缺失仅做被动/只读分析；不得强制或绕过门禁
- 场景:数据库评估铁律与暴露面|判据:生产库禁止破坏性语句除非明确允许，scope 写清实例/账号权限/是否允许写删；查网络暴露与错误绑定 0.0.0.0、TLS、是否未授权或弱口令|转向:SQL 注入类应用面转 web；云托管 RDS 配置转 cloud
- 场景:认证授权与危险功能|判据:核账号角色与 grantee、敏感表访问控制、危险配置(file_priv/xp_cmdshell/COPY PROGRAM/load_file/UDF)、审计日志是否开启、备份快照权限|转向:从应用账号到 DBA 的横向转 pivot；获 OS 命令转 attack-chain
- 场景:利用链安全验证|判据:仅授权环境验证 Redis 写文件、UDF 提权等；区分配置缺陷与可利用链，避免未授权写删，只读验证优先|转向:仅配置问题按风险定级；可达 OS/横向则串成链
- 场景:Evidence→Finding→Path 与提报|判据:Evidence 记录 ID/来源/SHA-256(样本或制品哈希，无则标 n/a)/复现条件与结果；Finding 引证验证受影响点、根因与影响、校验状态与置信度及修复建议；Path 连接起点→验证步骤→目标及证据 ID|转向:输出脱敏 CVE/CNVD/bounty 报告，移除真实凭据/隐私，区分候选与已验证，明确未证实项
