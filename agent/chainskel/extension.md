# chains-extension L3 决策骨架（蒸馏自 reverse-skill browser-extension-reverse/SKILL.md；仅限安全验证）
- 场景:目标工作授权门禁|判据:明确 auth.status=granted，资产/表面/活动均在范围内，且有合法 network_profile 或明确授权的离线样本；若拟执行仓库脚本，须先披露准确命令及副作用并取得用户单独明确同意|转向:任一缺失仅做被动/只读分析；不得强制或绕过门禁
- 场景:扩展识别与包体|判据:确认目标是浏览器扩展(crx/xpi/解压目录)而非普通网页 JS(普通→web/js)；解包读 manifest.json，盘点 permissions/host_permissions/background/content_scripts|转向:普通或深度混淆页面 JS 转 web；投毒调查转 supply/malware
- 场景:权限面与逻辑还原|判据:评估过度权限(<all_urls>、webRequest、debugger)；定位 service_worker/background 入口、content_script 注入点与世界(isolated)；追 chrome.storage/IndexedDB 密钥与 runtime.sendMessage 消息传递|转向:扩展实现的签名/加密/代理逻辑还原转 rev；触达后端接口越权转 web
- 场景:动态验证|判据:开发者模式加载解压目录，chrome://extensions 查错，DevTools 附加 service worker；必要时浏览器 CDP 观测网络与消息，仅授权范围|转向:确认敏感数据外带/越权即为可利用链；仅权限过大按风险定级
- 场景:Evidence→Finding→Path 与提报|判据:Evidence 记录 ID/来源/SHA-256(样本或制品哈希，无则标 n/a)/复现条件与结果；Finding 引证验证受影响点、根因与影响、校验状态与置信度及修复建议；Path 连接起点→验证步骤→目标及证据 ID|转向:输出脱敏 CVE/CNVD/bounty 报告，移除真实凭据/隐私，区分候选与已验证，明确未证实项
