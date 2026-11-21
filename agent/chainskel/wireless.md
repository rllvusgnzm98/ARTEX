# chains-wireless L3 决策骨架（蒸馏自 reverse-skill wifi-wireless/radio-sdr/SKILL.md；仅限安全验证）
- 场景:目标工作授权门禁|判据:明确 auth.status=granted，资产/表面/活动均在范围内，且有合法 network_profile 或明确授权的离线样本；若拟执行仓库脚本，须先披露准确命令及副作用并取得用户单独明确同意|转向:任一缺失仅做被动/只读分析；不得强制或绕过门禁
- 场景:无线/射频法规与范围铁律|判据:无线与频谱发射法律风险高，必须书面授权、物理范围与频段；scope 写明目标 SSID/BSSID/场地或设备/频段、是否允许发射(默认只收)；禁止扫邻居网络、未授权 deauth、干扰公共通信|转向:任一缺失仅被动接收/识别；非 Wi-Fi 通用 RF 走 SDR 流程
- 场景:Wi-Fi 采集与离线评估|判据:合法环境进 monitor，airodump 锁定目标 BSSID/频道，仅对目标采 WPA 握手或 PMKID；hashcat/aircrack 离线评估口令策略与加密类型、客户端隔离、门户绕过|转向:企业无线隔离/门户问题转 web/pivot；近源物理转 attack-chain
- 场景:SDR 通用射频研究|判据:仅授权频段/屏蔽室；只收识别中心频率与调制，GNU Radio/URH 解调分析；重放仅屏蔽室且书面允许，先改无害字段确认解析|转向:帧结构/协议还原转 protocol；设备调试接口转 hardware
- 场景:Evidence→Finding→Path 与提报|判据:Evidence 记录 ID/来源/SHA-256(样本或制品哈希，无则标 n/a)/复现条件与结果；Finding 引证验证受影响点、根因与影响、校验状态与置信度及修复建议；Path 连接起点→验证步骤→目标及证据 ID|转向:输出脱敏 CVE/CNVD/bounty 报告，移除真实凭据/隐私，区分候选与已验证，明确未证实项
