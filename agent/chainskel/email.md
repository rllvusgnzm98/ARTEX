# chains-email L3 决策骨架（蒸馏自 reverse-skill email-security/SKILL.md；仅限安全验证）
- 场景:目标工作授权门禁|判据:明确 auth.status=granted，资产/表面/活动均在范围内，且有合法 network_profile 或明确授权的离线样本；若拟执行仓库脚本，须先披露准确命令及副作用并取得用户单独明确同意|转向:任一缺失仅做被动/只读分析；不得强制或绕过门禁
- 场景:邮件安全授权与头认证|判据:确认授权(样本邮件分析或租户配置评审)，不向真实用户二次投递恶意样本；取完整原始头看 Received 链、From/Return-Path 一致性，核 SPF/DKIM/DMARC 对齐结果|转向:未授权第三方域群发测试钓鱼一律禁止；OAuth 应用钓鱼/邮箱令牌转 identity
- 场景:内容与仿冒研判|判据:URL 沙箱与附件静态(联合 malware 分析)、仿冒品牌与回复地址差异、钓鱼与 BEC 商务邮件欺诈模式；IOC 可检测化|转向:附件深度分析转 rev/malware；凭据钓鱼落地后横向转 ad/pivot
- 场景:租户控制面|判据:评估反钓鱼策略、外部发件标记、MFA、OAuth app 同意治理；给出可落地加固建议|转向:身份联邦/令牌面转 identity；云租户配置转 cloud
- 场景:Evidence→Finding→Path 与提报|判据:Evidence 记录 ID/来源/SHA-256(样本或制品哈希，无则标 n/a)/复现条件与结果；Finding 引证验证受影响点、根因与影响、校验状态与置信度及修复建议；Path 连接起点→验证步骤→目标及证据 ID|转向:输出脱敏 CVE/CNVD/bounty 报告，移除真实凭据/隐私，区分候选与已验证，明确未证实项
