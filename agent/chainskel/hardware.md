# chains-hardware L3 决策骨架（蒸馏自 reverse-skill hardware-security/SKILL.md；仅限安全验证）
- 场景:目标工作授权门禁|判据:明确 auth.status=granted，资产/表面/活动均在范围内，且有合法 network_profile 或明确授权的离线样本；若拟执行仓库脚本，须先披露准确命令及副作用并取得用户单独明确同意|转向:任一缺失仅做被动/只读分析；不得强制或绕过门禁
- 场景:物理接触授权与安全|判据:先确认物理接触授权与设备归属、ESD/电源安全，默认只读探测、非破坏性优先；禁止未授权拆机或损坏他人设备|转向:无物理授权仅文档/固件离线分析；镜像分析转 firmware
- 场景:调试接口发现与评估|判据:拆解授权设备拍照标测试点，万用表找 GND/VCC/TX/RX 与逻辑电平(1.8/3.3/5V)，USB-TTL 只读日志记波特率；JTAG 枚举 IDCODE 评估是否锁定|转向:启动日志/引导打断取 shell 后转 priv；工控设备转 ot
- 场景:固件提取与启动链|判据:评估安全启动/加密 Flash 可行性(非破坏优先)，提取 Flash 镜像并哈希保全后交 firmware/ghidra 分析；不盲刷固件|转向:镜像深挖转 firmware；协议/射频接口转 protocol/wireless
- 场景:Evidence→Finding→Path 与提报|判据:Evidence 记录 ID/来源/SHA-256(样本或制品哈希，无则标 n/a)/复现条件与结果；Finding 引证验证受影响点、根因与影响、校验状态与置信度及修复建议；Path 连接起点→验证步骤→目标及证据 ID|转向:输出脱敏 CVE/CNVD/bounty 报告，移除真实凭据/隐私，区分候选与已验证，明确未证实项
