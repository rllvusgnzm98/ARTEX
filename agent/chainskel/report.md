# chains-report L3 决策骨架（蒸馏自 reverse-skill case-review/SKILL.md；仅限安全验证）
- 场景:目标工作授权门禁|判据:明确 auth.status=granted，资产/表面/活动均在范围内，且有合法 network_profile 或明确授权的离线样本；若拟执行仓库脚本，须先披露准确命令及副作用并取得用户单独明确同意|转向:任一缺失仅做被动/只读分析；不得强制或绕过门禁
- 场景:提报前只读复核范围|判据:仅对已授权案例包做只读复核，不做侦察/利用/动态插桩/改目标；确认 scope.md 的授权、范围、network_profile 与离线样本身份就绪|转向:scope 字段缺失先补授权再谈提报；需继续分析转对应领域 skill
- 场景:Evidence→Finding→Path 可追溯性|判据:逐条核 Evidence ID 是否存在与可复现字段(来源/时间/SHA-256 或 n/a 加离线说明)、Finding 是否绑定 evidence_ids、Path 是否有合法 path_type 与证据引用、工作项与时间线是否指向已知 Evidence、有无游离 Evidence|转向:候选 Finding 未绑定证据不得判已验证；缺证据先补采
- 场景:完整性与提报质量|判据:对含 content_hash 与 artifact_path 的 Evidence 校验案例内制品(sha256:<64hex>，须在 case root 内)，哈希不符为硬失败；已验证 Finding 低置信需复核；strict 模式把警告视为阻断|转向:哈希污染先换干净副本重核；通过后进入报告生成
- 场景:Evidence→Finding→Path 与提报|判据:Evidence 记录 ID/来源/SHA-256(样本或制品哈希，无则标 n/a)/复现条件与结果；Finding 引证验证受影响点、根因与影响、校验状态与置信度及修复建议；Path 连接起点→验证步骤→目标及证据 ID|转向:输出脱敏 CVE/CNVD/bounty 报告，移除真实凭据/隐私，区分候选与已验证，明确未证实项
