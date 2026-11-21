# chains-identity L3 决策骨架（蒸馏自 reverse-skill identity-federation/SKILL.md；仅限安全验证）
- 场景:目标工作授权门禁|判据:明确 auth.status=granted，资产/表面/活动均在范围内，且有合法 network_profile 或明确授权的离线样本；若拟执行仓库脚本，须先披露准确命令及副作用并取得用户单独明确同意|转向:任一缺失仅做被动/只读分析；不得强制或绕过门禁
- 场景:联邦登录流测绘|判据:先画清 User→SP→IdP→Token→SP，固定 issuer/client_id/redirect_uri 白名单与 /.well-known/openid-configuration、SAML metadata；禁止对真实用户账户做会触发锁定的暴力尝试|转向:流不清先补抓重定向链；纯 API 的 JWT 面转 web
- 场景:OAuth/OIDC 授权码与令牌劫持|判据:redirect_uri 必须精确匹配(子串/通配/路径/@/IDN 同形均算缺陷)，state 绑定会话防 CSRF，核对 PKCE 是否缺失，看 code/token 能否经 Referer 或 open redirect 带到外域|转向:能把 code/token 带到外域即 ATO 链,接 web 的 open redirect/XSS;校验严转 nonce 重放/issuer 混淆
- 场景:SAML 断言可信性|判据:验证签名覆盖范围(是否只签 assertion 不签 Response、XSW 签名包裹)、algorithm 降级/alg=none、证书可否替换、Audience/Recipient/NotOnOrAfter 是否校验|转向:签名铁打转多租户 issuer 混淆;断言可改转伪造身份后的越权
- 场景:会话与登出完整性|判据:登录前后 session 是否轮换(会话固定)、登出/改密是否使 token 失效、refresh token 是否轮换、单点登出是否全局生效|转向:令牌不失效转长期劫持;单点登出缺失转跨 SP 横向
- 场景:Evidence→Finding→Path 与提报|判据:Evidence 记录 ID/来源/SHA-256/IdP 与 SP 标识/复现条件与结果;Finding 引证验证受影响流、根因(签名/校验/绑定缺陷)、可达性与影响;Path 连接登录起点→验证步骤→接管目标及证据 ID|转向:输出脱敏 CVE/CNVD/bounty 报告与修复建议,移除真实令牌/身份/断言,明确未证实项
