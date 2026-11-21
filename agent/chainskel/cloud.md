# chains-cloud L3 决策骨架（蒸馏自 reverse-skill cloud-k8s/SKILL.md；仅限安全验证）
- 场景:目标工作授权门禁|判据:明确 auth.status=granted，资产/表面/活动均在范围内，且有合法 network_profile 或明确授权的离线样本；若拟执行仓库脚本，须先披露准确命令及副作用并取得用户单独明确同意|转向:任一缺失仅做被动/只读分析；不得强制或绕过门禁
- 场景:身份与边界确认|判据:先定当前身份(云 AK/SK、K8s SA、节点 SSH)与范围(单账号/单 cluster/单 namespace)，network_profile=authorized_target_only;MUST NOT 扫其他租户或默认全网扫|转向:身份不明先 sts get-caller-identity / kubectl auth can-i --list;越界即停
- 场景:云控制面与元数据 SSRF|判据:IMDSv1 可直取临时凭据(v2 需 token),169.254.169.254 链先验真实服务端出口;公开桶/错误 ACL 以最小只读验证;PassRole/可扮演角色才算提权|转向:元数据拿到角色凭据转云内横向;只读受限转配置与公开资源盘点
- 场景:容器逃逸候选|判据:privileged / hostPath / hostNetwork、危险 capabilities(SYS_ADMIN)、可写宿主机路径、docker.sock 挂载才是逃逸原语;镜像历史与已知 CVE 需证明实际可达|转向:具备原语在授权隔离环境做有界无害验证;仅配置疑点保留静态证据,不强行逃逸
- 场景:K8s RBAC 与机密|判据:kubectl auth can-i --list 实测而非只读 RoleBinding;看 SA token 权限、能否 create pod/exec、读 secret、缺失 NetworkPolicy/admission、etcd/dashboard 暴露;区分可达与理论|转向:高权 SA 转接管 namespace/cluster;镜像链问题转 supply-chain
- 场景:Evidence→Finding→Path 与提报|判据:Evidence 记录 ID/来源/SHA-256/账号或 cluster 标识/命令与复现条件及结果;Finding 引证验证身份边界、根因(配置/权限/暴露)、可达性与影响;Path 连接入口→验证步骤→云资源目标及证据 ID|转向:输出脱敏 CVE/CNVD/bounty 报告与加固建议,移除密钥/凭据/账号标识,明确未证实与未执行的破坏性项
