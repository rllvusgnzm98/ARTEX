# chains-client L3 决策骨架（蒸馏自 reverse-skill thick-client/SKILL.md；仅限安全验证）
- 场景:目标工作授权门禁|判据:明确 auth.status=granted，资产/表面/活动均在范围内，且有合法 network_profile 或明确授权的离线样本；若拟执行仓库脚本，须先披露准确命令及副作用并取得用户单独明确同意|转向:任一缺失仅做被动/只读分析；不得强制或绕过门禁
- 场景:厚客户端信任边界建图|判据:确认目标是桌面厚客户端(Electron/Qt/.NET WinForms/WPF 或 C/S)，非纯 Web；画进程树/子进程/驱动服务、监听端口与出站域名、本地敏感路径(%APPDATA%/Keychain/注册表)|转向:纯协议分析转 protocol；自动更新供应链转 supply
- 场景:本地攻击面|判据:查明文配置/硬编码密钥/调试开关、DLL 劫持与搜索顺序(Windows)、SQLite 等本地库权限与加密、IPC/命名管道谁可连接与是否鉴权|转向:本地提权/逃逸转 priv；.NET 转 rev、Electron 解 asar 后转 web/rev
- 场景:网络面与更新链|判据:系统代理/自定义 TLS 与证书钉扎(联合 Frida 绕过)、客户端隐藏的管理接口越权、自动更新通道完整性与代码签名验证|转向:API 越权转 web；更新包签名缺陷可达则升级为可利用链
- 场景:Evidence→Finding→Path 与提报|判据:Evidence 记录 ID/来源/SHA-256(样本或制品哈希，无则标 n/a)/复现条件与结果；Finding 引证验证受影响点、根因与影响、校验状态与置信度及修复建议；Path 连接起点→验证步骤→目标及证据 ID|转向:输出脱敏 CVE/CNVD/bounty 报告，移除真实凭据/隐私，区分候选与已验证，明确未证实项
