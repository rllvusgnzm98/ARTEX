# chains-supply L3 决策骨架（蒸馏自 reverse-skill supply-chain-security/SKILL.md；仅限安全验证）
- 场景:目标工作授权门禁|判据:明确 auth.status=granted，资产/表面/活动均在范围内，且有合法 network_profile 或明确授权的离线样本；若拟执行仓库脚本，须先披露准确命令及副作用并取得用户单独明确同意|转向:任一缺失仅做被动/只读分析；不得强制或绕过门禁
- 场景:供应链面测绘与分层|判据:按源码信任→构建管道→制品分发→运行时→持续监控分层固定资产(仓库/CI 配置/镜像/SBOM)；生成 SBOM(CycloneDX/SPDX/syft)盘点直接与传递依赖、维护状态与许可证|转向:仅 Web 应用面转 web；容器/K8s 准入与 IAM 转 cloud
- 场景:SCA 告警可达性验证|判据:SCA 告警≠实际风险(多数不可达)；筛 CVSS≥7 且有 PoC 的项，用数据流/调用图切片追踪用户输入→漏洞函数的可达路径，隔离环境验证 PoC 后再定级|转向:不可达仅记为信息项；需源码确证转 audit
- 场景:CI/CD 管道与制品完整性|判据:审 Pipeline as Code 注入面、第三方 Action 是否锁 commit SHA 而非 tag、Runner 隔离、密钥是否硬编码；校验制品签名(cosign)/校验和/SBOM attest 是否齐备|转向:发现依赖混淆/typosquat/投毒可达则升级为可利用链；仅配置缺陷按风险定级
- 场景:Evidence→Finding→Path 与提报|判据:Evidence 记录 ID/来源/SHA-256(样本或制品哈希，无则标 n/a)/复现条件与结果；Finding 引证验证受影响点、根因与影响、校验状态与置信度及修复建议；Path 连接起点→验证步骤→目标及证据 ID|转向:输出脱敏 CVE/CNVD/bounty 报告，移除真实凭据/隐私，区分候选与已验证，明确未证实项
