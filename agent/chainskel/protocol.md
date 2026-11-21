# chains-protocol L3 决策骨架（蒸馏自 reverse-skill protocol-reverse/SKILL.md；仅限安全验证）
- 场景:目标工作授权门禁|判据:明确 auth.status=granted，资产/表面/活动均在范围内，且有合法 network_profile 或明确授权的离线样本；若拟执行仓库脚本，须先披露准确命令及副作用并取得用户单独明确同意|转向:任一缺失仅做被动/只读分析；不得强制或绕过门禁
- 场景:样本分诊与方向标记|判据:固定样本来源(PCAP/代理导出/客户端日志/二进制)与 SHA-256,标方向 C→S/S→C、握手/心跳/重连;辨固定头/魔数/长度字段/TLV/定长;是否压缩或帧内加密|转向:纯 HTTP 参数签名转 js-reverse;仅 TLS 证书问题转 pentest-tools
- 场景:帧布局还原|判据:对齐多条同类消息找不变字节与自增序列号;长度字段定端序与含头与否;定位 CRC/checksum/HMAC 位置;据此画状态机 Connect→Auth→Ready→Req/Resp→Close|转向:字段不稳先扩样本;需客户端算法转 ida-reverse/apk-reverse
- 场景:序列化与加密恢复|判据:Protobuf 用 protoc --decode_raw / blackboxprotobuf 恢复 .proto;gRPC 认 HTTP/2 头+protobuf 体;加密找客户端密钥派生(so/dll/JS)再解;重放仅授权 scope 内先改无害字段|转向:无 .proto 转 decode_raw 字段推断;密钥在客户端转对应逆向 skill
- 场景:重放与影响验证|判据:仅对授权目标重放,先改无害字段确认解析再谈敏感操作;序列号/时间戳/签名字段须同步否则无效;并发与状态机违规点到为止|转向:重放可控转 api-security/pentest-tools 利用;影响无法无害证明则报告静态还原结论
- 场景:Evidence→Finding→Path 与提报|判据:Evidence 记录 ID/来源/SHA-256/原始 hex 摘录/解码命令/复现条件与结果;Finding 引证验证消息布局或状态机、根因与影响;Path 连接样本起点→还原/验证步骤→目标及证据 ID|转向:输出脱敏报告与消息字典,原始 hex 与密钥只留脱敏摘要,明确未验证假设
