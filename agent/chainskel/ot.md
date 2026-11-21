# chains-ot L3 决策骨架（蒸馏自 reverse-skill ot-ics/SKILL.md；仅限安全验证）
- 场景:目标工作授权门禁|判据:明确 auth.status=granted，资产/表面/活动均在范围内，且有合法 network_profile 或明确授权的离线样本；若拟执行仓库脚本，须先披露准确命令及副作用并取得用户单独明确同意|转向:任一缺失仅做被动/只读分析；不得强制或绕过门禁
- 场景:工控安全铁律与分区|判据:工控误操作可致物理危害，默认 passive-first；ready_for_act 前禁止对 PLC 写线圈/寄存器、禁止全网高速扫描生产 OT、禁止中断安全仪表系统(SIS)；按 Purdue L0–L5 画分区与跨区通道|转向:任一边界不清仅被动识别；固件深挖转 firmware
- 场景:被动与只读评估|判据:SPAN/镜像 PCAP 交 Wireshark 工控 dissector 或 protocol 还原；离线审工程文件(TIA/RSLogix 导出)；默认口令与明文协议(Modbus 无认证)记为 Finding，不写盘改值|转向:私有/二进制工控协议还原转 protocol；IT/OT 边界横向转 ad/pivot
- 场景:受限主动与固件面(仅授权)|判据:仅维护窗口、低速、只读功能码优先，每步 Evidence，异常立即停止通报；控制器固件版本→CVE 映射，不盲刷固件，离线镜像分析|转向:需镜像提取转 firmware/hardware；影响须含物理/过程说明
- 场景:Evidence→Finding→Path 与提报|判据:Evidence 记录 ID/来源/SHA-256(样本或制品哈希，无则标 n/a)/复现条件与结果；Finding 引证验证受影响点、根因与影响、校验状态与置信度及修复建议；Path 连接起点→验证步骤→目标及证据 ID|转向:输出脱敏 CVE/CNVD/bounty 报告，移除真实凭据/隐私，区分候选与已验证，明确未证实项
