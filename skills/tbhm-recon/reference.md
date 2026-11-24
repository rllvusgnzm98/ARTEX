# TBHM Recon Methodology — 技术参考手册

本手册收录 Jason Haddix TBHM 2026 Core 课程中所有关键 Recon 命令与实战语法。

---

## 1. ASN 探测语法
- **查询 ASN**：在 `https://bgp.he.net` 或 `https://dnschecker.org/` 输入公司名称。
- **ASNmap 转 IP 范围**：
  ```bash
  asnmap -a AS394161 -silent
  ```
- **Naabu 端口联动**：
  ```bash
  echo AS394161 | asnmap -silent | naabu -p 80,443,8080,8443,8000,9000,3000,5000 -silent -o ports.txt
  ```

---

## 2. Microsoft 365 / Exchange 租户提取
- 脚本语法：
  ```bash
  bash tenant-domains.sh -d <target.com>
  ```
- 原理：利用 `autodiscover-s.outlook.com` 接口获取 FederationInformation，提取包含在该租户下的所有组织命名空间。

---

## 3. Shodan 被动查询语法
- **Karma v2**：
  ```bash
  bash karma_v2 -d <target.com> --limit -1 -deep
  ```
- **Shosubgo**：
  ```bash
  shosubgo -d <target.com> -s <SHODAN_API_KEY>
  ```
- **常用 Shodan 过滤语法**：
  - `ssl.cert.subject.CN:"target.com"`
  - `ssl:"target.com" 200`
  - `org:"Target Company"`

---

## 4. DMARC 逆向关联查询
- 核心原理：解析 `_dmarc.<domain>` 的 TXT 记录，匹配 `rua=mailto:...` 与 `ruf=mailto:...` 的接收域。
- 使用配套工具：
  ```bash
  python3 scripts/live_dmarc_lookup.py <target.com>
  ```

---

## 5. 子域名暴力破解与变异
- **PureDNS 高性能爆破**（依赖已清洗的公共 DNS 解析器）：
  ```bash
  puredns bruteforce wordlist.txt target.com -r resolvers.txt -w puredns_out.txt
  ```
- **dnsgen 组合变异**：
  ```bash
  cat known_subs.txt | dnsgen - | puredns resolve -r resolvers.txt -w resolved_perms.txt
  ```

---

## 6. GitHub Recon Dorking 常用规则
- `org:<Target> "api_key"`
- `org:<Target> "secret_key"`
- `org:<Target> filename:.env`
- `org:<Target> "Authorization: Bearer"`
- `org:<Target> filename:wp-config.php`
- `org:<Target> filename:credentials.json`
