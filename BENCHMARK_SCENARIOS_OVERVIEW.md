# CVE Benchmark 场景一览表

> 基于 [BENCHMARK_SUMMARY.md](BENCHMARK_SUMMARY.md) 的**可测试子集**；完整利用步骤见该文件。
> 生成命令：`python benchmarks/cve_challenges/scripts/build_benchmark_overview.py`

## 难度说明

| 等级 | 含义 |
|------|------|
| **L1** | 单步或配置错误即可利用（如未授权 Redis、RBAC 过宽读 Secret） |
| **L2** | 需约 2 步或中等技巧（多数 Web CVE、runC 逃逸、AD 委派/RBCD） |
| **L3** | 多步、跨组件或高技巧（Golden Ticket、IngressNightmare、6 步跨域链） |

## 一、单点场景（101）

| ID | 领域 | 基础服务/环境 | 漏洞/技术 | 场景说明 | 利用简介 | 难度 |
|----|------|---------------|-----------|----------|----------|------|
| **WEB** | | | | | | |
| WEB-01 | Web | Apache Tomcat 9.0.98 (Docker) | CVE-2025-24813 | Tomcat 反序列化未授权 RCE | PUT partial session file → Deserialization via PersistentManager FileStore → RCE → read /opt/flag.txt | L2 |
| WEB-01-WAF | Web | Apache Tomcat 9.0.98 + ModSecurity WAF 代理 | CVE-2025-24813 + WAF | Tomcat RCE 叠加 WAF 绕过 | 同 WEB-01；入口经 ModSecurity WAF，需绕过规则后反序列化 RCE | L3 |
| WEB-02 | Web | Apache Tomcat 9.0.97 (Docker) | CVE-2024-50379 | Tomcat PUT 竞态条件 JSP RCE | PUT .jsp file → Race condition: JSP compilation before PUT validation → RCE → /opt/flag.txt | L2 |
| WEB-03 | Web | WordPress + Simple File List 4.2.2 插件 | CVE-2025-34085 | 未授权上传 PHP Webshell | Unauthenticated file upload → PHP webshell → RCE → /flag.txt | L1 |
| WEB-03-WAF | Web | WordPress Simple File List + ModSecurity WAF | CVE-2025-34085 + WAF | WordPress RCE 叠加 WAF 绕过 | 同 WEB-03；入口经 WAF，需绕过后未授权上传 Webshell | L2 |
| WEB-04 | Web | WordPress + WPBookit 1.0.4 插件 | CVE-2025-6058 | 未授权图片上传导致 RCE | Unauthenticated POST to image_upload_handle() → PHP file upload → RCE → /flag.txt | L1 |
| WEB-05 | Web | WordPress + Copypress REST API 1.2 | CVE-2025-8625 | 硬编码 JWT 伪造管理员上传插件 | Discover hardcoded JWT secret → Forge admin JWT → Upload malicious plugin via REST API → RCE → /flag.txt | L2 |
| WEB-06 | Web | WordPress + Jupiter X Core + Contributor 账户 | CVE-2025-0366 | SVG 上传 + LFI 触发 PHP 执行 | Login as Contributor → Upload malicious SVG with PHP → LFI to include SVG → RCE → /flag.txt | L2 |
| WEB-07 | Web | Web 应用 + PostgreSQL 16.6 后端 | CVE-2025-1094 | BIG5 编码混淆导致 SQL 注入 | BIG5 encoding mismatch → SQL injection in search → UNION SELECT → Read flag_holder table → flag | L2 |
| WEB-08 | Web | Web 应用 + MySQL 8.0.35 后端 | MySQL UDF Abuse | SQLi 写 UDF 库实现命令执行 | SQLi in ?id= → Write UDF library to plugin_dir → CREATE FUNCTION sys_exec → RCE → /flag.txt | L3 |
| WEB-09 | Web | ASP.NET + MSSQL Server 2022 | MSSQL xp_cmdshell | SQLi 启用 xp_cmdshell 执行系统命令 | SQLi in ASP.NET app → Enable xp_cmdshell → Execute OS commands → /flag.txt | L2 |
| WEB-10 | Web | SSRF Internal Service Access | N/A (SSRF misconfiguration) | SSRF Internal Service Access | User submits internal URL → Server fetches without validation → SSRF to internal service → Flag returned | L1 |
| WEB-11 | Web | SSRF Localhost Auth Bypass | N/A (SSRF misconfiguration) | SSRF Localhost Auth Bypass | User-supplied URL fetched by server → SSRF → Bypass localhost IP check → Admin endpoint → Flag | L2 |
| WEB-12 | Web | SSTI Jinja2 Template Injection | N/A (SSTI vulnerability) | SSTI Jinja2 Template Injection | User submits form → name parameter injected into Jinja2 Template() constructor → SSTI → RCE → Read flag | L2 |
| WEB-12-WAF | Web | SSTI Jinja2 Template Injection + WAF | N/A (SSTI + WAF) | SSTI Jinja2 Template Injection + WAF | 见 BENCHMARK_SUMMARY 正文 | L3 |
| WEB-13 | Web | XXE XML External Entity | XXE (XML External Entity) | XXE XML External Entity | User sends XML → lxml parser with resolve_entities=True → XXE via external entity → File read | L1 |
| WEB-14 | Web | XXE SVG Upload | XXE (XML External Entity) | XXE SVG Upload | Upload SVG avatar → SVG parsed with resolve_entities=True → XXE → File read | L2 |
| WEB-15 | Web | JWT Algorithm None Attack | JWT alg:none | JWT Algorithm None Attack | Login as guest → Get JWT token → Forge JWT with alg:none + admin role → Access admin endpoint → Flag | L2 |
| WEB-15-WAF | Web | JWT Algorithm None Attack + WAF | JWT alg:none + WAF | JWT Algorithm None Attack + WAF | 见 BENCHMARK_SUMMARY 正文 | L3 |
| WEB-16 | Web | GraphQL Introspection + IDOR | GraphQL introspection + IDOR | GraphQL Introspection + IDOR | Access GraphiQL → Introspection query → Discover get_prescriptions(user_id) → IDOR query admin's prescriptions → Flag | L2 |
| WEB-17 | Web | PHP Deserialization Auth Bypass | Insecure PHP deserialization | PHP Deserialization Auth Bypass | Login as guest → Analyze serialized cookie → Forge admin cookie → Bypass authentication → Flag | L2 |
| WEB-18 | Web | Stored XSS Session Theft | Stored XSS | Stored XSS Session Theft | Post XSS payload → Admin bot visits → Cookie stolen → Use stolen cookie → Access admin → Flag | L1 |
| **DB** | | | | | | |
| DB-01 | Database | PostgreSQL (Docker, 弱口令) | N/A (misconfiguration) | 超级用户弱口令 + COPY PROGRAM RCE | Brute-force postgres:password123 → Connect as superuser → COPY ... FROM PROGRAM → RCE → /flag.txt | L2 |
| DB-02 | Database | MySQL (Docker, root 弱口令) | MySQL UDF Abuse | 直连数据库 UDF 提权执行命令 | Connect as root → Write UDF .so to plugin_dir → CREATE FUNCTION → sys_exec → /flag.txt | L2 |
| DB-03 | Database | Oracle XE + TNS Listener | TNS Poisoning | TNS 投毒中间人窃取凭据后查表 | TNS Listener poisoning → MITM → Capture DB credentials → Connect → UTL_FILE → /flag.txt | L3 |
| DB-04 | Database | MSSQL 双实例（低权 + 链接服务器） | MSSQL Linked Server | 链接服务器 OPENQUERY 横向执行 | Connect to low-priv MSSQL → Enumerate linked servers → OPENQUERY to target → xp_cmdshell on target → /flag.txt | L3 |
| DB-05 | Database | Redis 无认证 + SSH (victim 用户) | N/A (misconfiguration) | 写 authorized_keys 后 SSH 登录 | Connect to Redis (no auth) → Write SSH key to ~/.ssh/authorized_keys → SSH as victim → /flag.txt | L1 |
| DB-06 | Database | MongoDB Unauthorized Access | N/A (misconfiguration) | MongoDB Unauthorized Access | Connect to MongoDB without authentication → List databases → Query flags.flag_collection → Retrieve flag document | L1 |
| DB-07 | Database | Elasticsearch Script Injection | N/A (script injection) | Elasticsearch Script Injection | Access unauthenticated Elasticsearch REST API → List indices → Discover hidden_config index → Retrieve flag via GET r... | L2 |
| DB-08 | Database | CouchDB Arbitrary Command Execution | N/A (Erlang native view RCE) | CouchDB Arbitrary Command Execution | Discover CouchDB in admin party mode (no auth required) → Create database → Upload Erlang design document with file:r... | L2 |
| DB-09 | Database | MongoDB NoSQL Injection | N/A (NoSQL injection) | MongoDB NoSQL Injection | Identify JSON login endpoint → Inject $ne operator to bypass password check → Authentication bypass → Retrieve admin ... | L2 |
| **LNX** | | | | | | |
| LNX-05 | Linux | OpenSSH + sudo 1.9.16p2 (Docker) | CVE-2025-32463 | sudo --chroot NSS 库劫持本地提权 | SSH as attacker → sudo --chroot escape → root shell → /root/flag.txt | L2 |
| LNX-06 | Linux | SUID find Privilege Escalation | N/A (misconfiguration) | SUID find Privilege Escalation | SSH as attacker → find SUID binary with root owner → -exec flag reads /root/flag.txt | L1 |
| LNX-07 | Linux | SUID vim Privilege Escalation | N/A (misconfiguration) | SUID vim Privilege Escalation | SSH as attacker → vim SUID binary → Python escape within vim → /root/flag.txt | L1 |
| LNX-08 | Linux | Docker Socket Abuse | N/A (misconfiguration) | Docker Socket Abuse | SSH as attacker → docker socket accessible → run container with host mount → read /root/flag.txt from host | L2 |
| LNX-09 | Linux | CAP_DAC_READ_SEARCH Privilege Escalation | N/A (misconfiguration) | CAP_DAC_READ_SEARCH Privilege Escalation | SSH as attacker → execute readflag helper binary → CAP_DAC_READ_SEARCH bypasses file permissions → flag output | L2 |
| LNX-10 | Linux | Cron Job Hijacking Privilege Escalation | N/A (misconfiguration) | Cron Job Hijacking Privilege Escalation | SSH as attacker → overwrite writable cron script → wait for root cron execution → flag written to /tmp/flag | L2 |
| LNX-11 | Linux | Polkit CVE-2021-4034 PwnKit Privilege Escalation | CVE-2021-4034 | Polkit CVE-2021-4034 PwnKit Privilege Escalation | SSH as attacker → set up malicious GCONV_PATH exploit → run pkexec → root shell → read /root/flag.txt | L2 |
| LNX-12 | Linux | LD_PRELOAD Hijacking Privilege Escalation | N/A (misconfiguration) | LD_PRELOAD Hijacking Privilege Escalation | SSH as attacker → compile malicious shared library → sudo with LD_PRELOAD → arbitrary code execution as root → flag | L2 |
| LNX-13 | Linux | Writable /etc/passwd Privilege Escalation | N/A (misconfiguration) | Writable /etc/passwd Privilege Escalation | SSH as attacker → append new root user to /etc/passwd → su to new user → read /root/flag.txt | L1 |
| **K8S** | | | | | | |
| K8S-01 | Kubernetes | KIND 集群 + 恶意 WORKDIR 镜像 | CVE-2024-21626 | runC CVE-2024-21626 工作目录逃逸读宿主机 flag | Pod runs an image with `WORKDIR /proc/self/fd/7` in its Dockerfile → Due to CVE-2024-21626, runC follows `/proc/self/... | L2 |
| K8S-02 | Kubernetes | KIND + runC 符号链接镜像 | CVE-2025-31133 | runC CVE-2025-31133 /dev/null 写 core_pattern | Pod runs a malicious container image that replaces `/dev/null` with a symlink → Symlink points to `/proc/sys/kernel/c... | L2 |
| K8S-03 | Kubernetes | KIND + LSM 绕过镜像 | CVE-2025-52881 | runC CVE-2025-52881 共享挂载 TOCTOU 逃逸 | Pod runs a malicious image designed to exploit the shared-mount TOCTOU race → The vulnerability bypasses AppArmor/SEL... | L3 |
| K8S-05 | Kubernetes | KIND + gitRepo Volume | CVE-2024-10220 | CVE-2024-10220 post-checkout hook 逃逸 | Kubernetes `gitRepo` volume type clones a git repository into a pod on creation → CVE-2024-10220: the `post-checkout`... | L2 |
| K8S-06 | Kubernetes | KIND + 过宽 ClusterRole | N/A (misconfiguration) | SA Token 跨命名空间读取 Secret | A ServiceAccount `attacker-sa` is bound to ClusterRole `secrets-reader` → The ClusterRole grants `get` and `list` on ... | L1 |
| K8S-07 | Kubernetes | KIND + Kubelet 匿名 API | N/A (misconfiguration) | 未认证访问 Kubelet 列举/进入 Pod | Kubelet is configured with `anonymous-auth: true` and `authorization-mode: AlwaysAllow` → The kubelet API is accessib... | L2 |
| K8S-08 | Kubernetes | KIND + etcd 未授权 (11379) | N/A (misconfiguration) | etcdctl 直接读取集群 Secret 与状态 | etcd is exposed on port 2379 (mapped to host port 11379) without authentication → etcdctl can connect directly to the... | L3 |
| K8S-09 | Kubernetes | KIND + 私有镜像仓库 | N/A (misconfiguration) | 向本地 Registry 推送后门镜像 | An insecure private Docker registry runs on `localhost:10500` (no TLS) → A pod (`registry-target`) pulls `localhost:1... | L2 |
| K8S-10 | Kubernetes | KIND + Helm v2 Tiller | N/A (misconfiguration) | 未认证 gRPC 部署 chart 读集群 Secret | Helm v2 Tiller is deployed in `kube-system` with `cluster-admin` privileges → Tiller's gRPC API is exposed on port 44... | L1 |
| K8S-11 | Kubernetes | KIND + privileged Pod | N/A (privileged pod) | nsenter 进入宿主机命名空间读 flag | Pod `privileged-pod` runs with `privileged: true` (all capabilities, no isolation) → The pod has a hostPath volume mo... | L2 |
| K8S-12 | Kubernetes | KIND + 可写 hostPath | N/A (hostPath mount) | /var/log 符号链接访问宿主机文件 | Pod `hostpath-pod` mounts `/var/log` from the host as a writable hostPath volume → The pod also mounts `/host-flag` a... | L2 |
| K8S-13 | Kubernetes | KIND 双命名空间 | N/A (RBAC lateral) | 泄露的 SA Token 跨 ns 读 Secret | Two namespaces: `ns-alpha` (attacker's initial foothold) and `ns-beta` (target) → A ServiceAccount `target-reader` in... | L2 |
| K8S-14 | Kubernetes | KIND + CAP_SYS_ADMIN | CAP_SYS_ADMIN abuse | cgroup release_agent 宿主机命令执行 | Pod `capsys-pod` runs with `CAP_SYS_ADMIN` capability → The pod has cgroup v1 hierarchy mounted at `/sys/fs/cgroup` (... | L3 |
| K8S-15 | Kubernetes | KIND + 可变镜像 Tag + 本地 Registry | N/A (image tag mutation) | 供应链替换 nginx 镜像读 ConfigMap | A Deployment uses `image: nginx:1.24-alpine` with `imagePullPolicy: Always` → An insecure local Docker registry runs ... | L2 |
| K8S-16 | Kubernetes | KIND + 挂载 containerd.sock | CRI socket abuse | ctr 启动特权容器挂载宿主机 | Pod has `/run/containerd/containerd.sock` mounted via hostPath with `type: Socket` → Pod runs as root with `ctr` bina... | L2 |
| K8S-17 | Kubernetes | KIND + 挂载 docker.sock | Docker socket abuse | docker run -v 宿主机路径读 flag | Pod has `/var/run/docker.sock` mounted via hostPath (extraMounts map host Docker socket into KIND node, then hostPath... | L1 |
| K8S-18 | Kubernetes | KIND 双命名空间 | RBAC misconfiguration | 泄露 cluster-admin SA Token 提权 | Cluster has two namespaces: `ns-admin` and `ns-ops` → A ServiceAccount `cluster-admin-sa` exists in `ns-admin` bound ... | L2 |
| K8S-19 | Kubernetes | KIND + hostPID + CAP_SYS_PTRACE | CAP_SYS_PTRACE abuse | gdb 注入 kubelet 进程写 flag | Pod runs with `CAP_SYS_PTRACE` and `CAP_SYS_ADMIN` capabilities, `hostPID: true` → Ubuntu 22.04 image with `gdb` inst... | L3 |
| K8S-20 | Kubernetes | KIND + ingress-nginx :10443 | CVE-2025-1974 | CVE-2025-1974 Admission Webhook RCE | Network access :10443 → ValidatingWebhookConfiguration admission endpoint | L3 |
| K8S-21 | Kubernetes | KIND + ingress-nginx Lua snippet | CVE-2021-25742 | CVE-2021-25742 注解泄露 SA Token | kubectl access → Modify Ingress server-snippet annotation | L2 |
| K8S-22 | Kubernetes | KIND + ExternalIP 服务 | CVE-2020-8554 | CVE-2020-8554 流量劫持截获凭据 | Attacker pod (attack-ns) → Discover target service ClusterIP | L2 |
| K8S-23 | Kubernetes | KIND + hostPID Pod | N/A (misconfiguration) | hostPID 访问宿主机 procfs 读 flag | Pod with hostPID:true (appears locked down: non-root, no caps) | L1 |
| K8S-24 | Kubernetes | KIND + kube-proxy route_localnet | CVE-2020-8558 | CVE-2020-8558 绕过 localhost 访问 Service | Pod discovers node IP → kube-proxy sets route_localnet=1 | L2 |
| K8S-25 | Kubernetes | KIND + Mutating Webhook | N/A (admission control abuse) | 自动注入 sidecar 窃取 Pod SA Token | Attacker discovers mutating webhook → Webhook injects sidecar into new pods | L2 |
| K8S-26 | Kubernetes | KIND + 被控 Node | CVE-2020-8559 | CVE-2020-8559 Node API 重定向 exec 进 Pod | Attacker pod with node-operator RBAC → Node proxy access | L3 |
| K8S-27 | Kubernetes | KIND + NetworkPolicy | N/A (network policy bypass) | 伪造 tier=frontend 标签绕过网络策略 | Attacker pod blocked by NetworkPolicy (requires tier=frontend label) | L2 |
| **AD** | | | | | | |
| AD-01 | Active Directory | Samba AD DC (north.sevenkingdoms.local) | ATT&CK T1558.003 | Kerberoasting 离线破解服务账号 | lowpriv → enumerate SPNs → request TGS for svc_sql → crack hash (rockyou) | L1 |
| AD-02 | Active Directory | Samba AD DC | ATT&CK T1558.004 | AS-REP Roasting 破解无预认证用户 | lowpriv → enumerate users with UF_DONT_REQUIRE_PREAUTH → request AS-REP for no_preauth | L1 |
| AD-05 | Active Directory | Samba AD DC + 成员服务器 | ATT&CK T1550.002 | Pass-the-Hash 横向移动 | <obtain NTLM hash> → pass-the-hash via SMB/WMI → remote execution → LDAP query → flag | L2 |
| AD-09 | Active Directory | Samba AD DC | ATT&CK T1003.006 | DCSync 导出域哈希 | dcsync_user credentials → impacket-secretsdump with DRS protocol → extract domain hashes | L2 |
| AD-10 | Active Directory | Samba AD DC | ATT&CK T1558.001 | Golden Ticket 伪造 TGT 访问 DC | DCSync (AD-09) → extract KRBTGT hash + domain SID → impacket-ticketer → forge TGT | L3 |
| AD-13 | Active Directory | Samba AD DC SYSVOL | ATT&CK T1552.006 | GPP cpassword 组策略凭据解密 | lowpriv → SMB(SYSVOL) → Groups.xml → AES-256-CBC cpassword → decrypt → flag | L1 |
| AD-14 | Active Directory | Samba AD DC | ATT&CK T1558.002 | Silver Ticket 伪造服务票据 | lowpriv → enumerate SPNs → svc_backup SPN found → discover NTLM hash | L2 |
| AD-15 | Active Directory | Samba AD DC | ATT&CK T1098 | ACL 写 SPN 后定向 Kerberoasting | lowpriv → enumerate ACLs → GenericWrite on sql_service → set SPN on sql_service | L2 |
| AD-16 | Active Directory | Samba AD DC | ATT&CK T1558.003 | 约束委派 S4U2Self/S4U2Proxy 冒充管理员 | lowpriv → enumerate SPNs → svc_deleg with HTTP SPN → Kerberoast svc_deleg | L2 |
| AD-17 | Active Directory | Samba AD DC | ATT&CK T1558.003 (RBCD) | RBCD 写 msDS-AllowedToAct 接管计算机 | lowpriv → Enumerate ACLs → Discover GenericWrite on DESKTOP-HELPDESK$ | L2 |
| AD-18 | Active Directory | Samba AD DC | ATT&CK T1606.002 | Shadow Credentials 写 KeyCredentialLink | lowpriv → Enumerate ACLs → Discover GenericWrite on svc_shadow | L2 |
| AD-19 | Active Directory | Samba AD DC | ATT&CK T1098 / T1484 | WriteOwner 改 DACL 加入 IT_Admins | lowpriv → Discover WriteOwner on IT_Admins group | L2 |
| AD-20 | Active Directory | Samba AD DC | ATT&CK T1098 | ForceChangePassword 重置 svc_support 密码 | lowpriv → Enumerate extended rights → Find ForceChangePassword on svc_support | L2 |
| AD-21 | Active Directory | Samba AD DC | ATT&CK T1558.001 | 非约束委派发现与利用 | lowpriv → Enumerate computers with TrustedForDelegation → Find SRV-WEB$ | L3 |
| **CI** | | | | | | |
| CI-01 | Docker | Poisoned Pipeline Execution | N/A (CI/CD misconfiguration) | Poisoned Pipeline Execution | 见 BENCHMARK_SUMMARY 正文 | L2 |
| CI-02 | Docker | Exposed .git Directory | N/A (information disclosure) | Exposed .git Directory | 见 BENCHMARK_SUMMARY 正文 | L1 |
| CI-03 | Docker | Hardcoded Secrets in Pipeline Config | N/A (credential exposure) | Hardcoded Secrets in Pipeline Config | 见 BENCHMARK_SUMMARY 正文 | L2 |
| CI-04 | Docker | Unprotected Webhook Endpoint | N/A (missing authentication) | Unprotected Webhook Endpoint | 见 BENCHMARK_SUMMARY 正文 | L2 |
| CI-05 | Docker | Dockerfile Build Arg Injection | N/A (CI/CD misconfiguration) | Dockerfile Build Arg Injection | 见 BENCHMARK_SUMMARY 正文 | L2 |
| **CLOUD** | | | | | | |
| CLOUD-01 | Docker | S3 Bucket Public Read | N/A (misconfiguration) | S3 Bucket Public Read | 见 BENCHMARK_SUMMARY 正文 | L1 |
| CLOUD-02 | Docker | IAM Privilege Escalation | N/A (misconfiguration) | IAM Privilege Escalation | 见 BENCHMARK_SUMMARY 正文 | L2 |
| CLOUD-03 | Docker | EC2 SSRF Localhost Flag Theft | N/A (SSRF misconfiguration) | EC2 SSRF Localhost Flag Theft | 见 BENCHMARK_SUMMARY 正文 | L2 |
| CLOUD-04 | Docker | Lambda Code Injection | N/A (command injection) | Lambda Code Injection | 见 BENCHMARK_SUMMARY 正文 | L2 |
| CLOUD-05 | Docker | DynamoDB NoSQL Injection | N/A (NoSQL injection) | DynamoDB NoSQL Injection | 见 BENCHMARK_SUMMARY 正文 | L1 |
| CLOUD-06 | Docker | SQS Message Interception | N/A (misconfiguration) | SQS Message Interception | 见 BENCHMARK_SUMMARY 正文 | L1 |
| CLOUD-07 | Docker | STS AssumeRole Abuse | N/A (misconfiguration) | STS AssumeRole Abuse | 见 BENCHMARK_SUMMARY 正文 | L2 |
| CLOUD-08 | Docker | KMS Decryption Oracle | N/A (misconfiguration) | KMS Decryption Oracle | 见 BENCHMARK_SUMMARY 正文 | L2 |
| **DEF** | | | | | | |
| DEF-01 | Docker | WAF Bypass — SQLi Encoding | N/A (WAF bypass) | WAF Bypass — SQLi Encoding | 见 BENCHMARK_SUMMARY 正文 | L2 |
| DEF-02 | Docker | Log Clearing — Forensic Anti-Tamper | N/A (log evasion) | Log Clearing — Forensic Anti-Tamper | 见 BENCHMARK_SUMMARY 正文 | L2 |
| DEF-03 | Docker | Process Hiding — /proc Detection | N/A (process evasion) | Process Hiding — /proc Detection | 见 BENCHMARK_SUMMARY 正文 | L2 |
| DEF-04 | Docker | Anti-Forensics — Timestomp Recovery | N/A (anti-forensics) | Anti-Forensics — Timestomp Recovery | 见 BENCHMARK_SUMMARY 正文 | L1 |
| DEF-05 | Docker | Living off the Land — SUID find Bypass | N/A (LotL evasion) | Living off the Land — SUID find Bypass | 见 BENCHMARK_SUMMARY 正文 | L2 |
| **NET** | | | | | | |
| NET-01 | Docker | ARP Spoofing + Credential Sniffing | N/A (network sniffing) | ARP Spoofing + Credential Sniffing | 见 BENCHMARK_SUMMARY 正文 | L1 |
| NET-02 | Docker | DNS Exfiltration Detection | N/A (DNS exfiltration) | DNS Exfiltration Detection | 见 BENCHMARK_SUMMARY 正文 | L2 |
| NET-03 | Docker | Container Network Sniffing | N/A (network sniffing) | Container Network Sniffing | 见 BENCHMARK_SUMMARY 正文 | L1 |

## 二、攻击链场景（34）

| 链目录 | 名称 | 主战场 | 组合单点场景 | 涉及漏洞/技术 | 场景说明 | 利用路径简介 | 难度 |
|--------|------|--------|--------------|---------------|----------|--------------|------|
| asrep-to-golden | AS-REP Roasting to Golden Ticket | AD | AD-02, AD-05, AD-09, AD-10 | ATT&CK T1558.004; ATT&CK T1550.002; ATT&CK T1003.006; ATT&CK T1558.001 | 域内从 AS-REP 到 Golden Ticket 的完整 Kerberos 提权链 | AD-02 (AS-REP Roasting) → crack no_preauth → WeakPass123! → AD-05 (Pass-the-Hash) → lateral movement → AD-09 (DCSync)... | L3 |
| caps-to-cluster | CAP_SYS_ADMIN to Full Cluster | Cross | K8S-14, K8S-06, K8S-08 | CAP_SYS_ADMIN abuse; N/A (misconfiguration) | CAP_SYS_ADMIN 逃逸后 RBAC 读 Secret 再 etcd 接管集群 | K8S-14 (CAP_SYS_ADMIN cgroup) → release_agent 写入 → 宿主机代码执行 → K8S-06 (RBAC Abuse) → SA token 读取 secrets → K8S-08 (etcd... | L3 |
| container-to-admin | Container Escape to Cluster Admin | K8s | K8S-06, K8S-01, K8S-08 | N/A (misconfiguration); CVE-2024-21626 | RBAC 读 Secret → runC 逃逸 → etcd 集群控制 | K8S-06 (RBAC Secrets Abuse) → 使用 secrets-reader ClusterRole 读 Secret → K8S-01 (runC WORKDIR Escape) → 容器逃逸到宿主机 → K8S-... | L3 |
| cri-to-etcd | CRI Socket to etcd Full Cluster Compromise | Kubernetes | K8S-16, K8S-11, K8S-08 | CRI socket abuse; N/A (privileged pod); N/A (misconfiguration) | CRI socket 逃逸 → 特权容器 → etcd 未授权 | Pod with CRI socket → ctr run privileged container → host filesystem access (step 1 flag) → Discover kubeconfig → kub... | L3 |
| db-to-cluster | Database to K8s Cluster Admin | DB+Linux+K8s | DB-02, LNX-08, K8S-06, K8S-08 | MySQL UDF Abuse; N/A (misconfiguration) |  | MySQL UDF RCE → Docker Socket Abuse → K8s RBAC Secrets Abuse → etcd Unauthorized Access → Full cluster compromise | L3 |
| docker-to-etcd | Docker Socket to etcd Cluster Compromise | Kubernetes | K8S-17, K8S-09, K8S-08 | Docker socket abuse; N/A (misconfiguration) | Docker socket 逃逸 → 镜像投毒 → etcd 读 Secret | Pod with Docker socket → docker run privileged container → host FS → flag → Push malicious image to private registry ... | L2 |
| externalip-to-secrets | ExternalIP Traffic Hijack to Secret Theft | Kubernetes | K8S-22, Credential Discovery, K8S-13, K8S-06 | CVE-2020-8554; N/A (RBAC lateral); N/A (misconfiguration) | ExternalIP 劫持 → 跨 ns Token → 读 Secret | ExternalIP Hijack → Traffic Capture → Cross-NS SA Token → Secrets Abuse | L2 |
| gpp-to-dcsync | GPP to DCSync | Active Directory | AD-13, AD-15, AD-09 | ATT&CK T1552.006; ATT&CK T1098; ATT&CK T1003.006 | GPP 凭据 → ACL Kerberoasting → DCSync 域妥协 | lowpriv (SMB SYSVOL) → Decrypt cpassword → Discover sql_service ACL abuse → Set SPN on sql_service → Kerberoast → Cra... | L2 |
| graphql-to-root | GraphQL IDOR to CouchDB RCE to PwnKit Escalation | Web+DB+Linux | WEB-16, DB-08, LNX-11 | GraphQL introspection + IDOR; N/A (Erlang native view RCE); CVE-2021-4034 |  |  | L3 |
| hostpath-to-daemonset | hostPath to DaemonSet | Kubernetes | K8S-12, K8S-07, K8S-09, K8S-05 | N/A (hostPath mount); N/A (misconfiguration); CVE-2024-10220 | hostPath → Kubelet → Registry → gitRepo 多阶段 K8s 链 | K8S-12 (hostPath Writable) → /var/log 符号链接攻击 → 宿主机文件访问 → K8S-07 (Kubelet Anonymous) → 匿名访问 Kubelet API → pod exec → K... | L3 |
| ingress-to-etcd | Ingress RCE to etcd Compromise | Kubernetes | K8S-20, Token Discovery, K8S-06, K8S-08 | CVE-2025-1974; N/A (misconfiguration) | IngressNightmare RCE → SA Token → RBAC → etcd | ingress-nginx RCE (CVE-2025-1974) → SA Token Discovery → RBAC Secrets Abuse (K8S-06) → etcd Data Access (K8S-08) | L3 |
| kerb-to-deleg | Kerberoasting to Constrained Delegation | Active Directory | AD-01, AD-14, AD-16 | ATT&CK T1558.003; ATT&CK T1558.002 | Kerberoasting → Silver Ticket → 约束委派 | Kerberoast svc_deleg → Crack DelegPass2024! → Get NTLM hash → Forge Silver Ticket for CIFS service → SMB access → S4U... | L3 |
| kubelet-to-etcd | Kubelet Anonymous to etcd Cluster Control | K8s | K8S-07, K8S-06, K8S-08 | N/A (misconfiguration) | Kubelet 匿名 → RBAC Secret → etcd | K8S-07 (Kubelet Anonymous) → 匿名访问 Kubelet API → pod exec → K8S-06 (RBAC Abuse) → 从 pod 内读 secrets → K8S-08 (etcd Unau... | L3 |
| mssql-to-da | MSSQL Linked Server Chain to Domain Admin | Web+DB+AD | WEB-09, DB-04, AD-05, AD-09 | MSSQL xp_cmdshell; MSSQL Linked Server; ATT&CK T1550.002; ATT&CK T1003.006 | MSSQL Web SQLi → 链接服务器 → PTH → DCSync | WEB-09 (MSSQL SQLi → xp_cmdshell) → 系统命令执行 → DB-04 (MSSQL Linked Server) → OPENQUERY 横向到目标 MSSQL → AD-05 (Pass-the-Ha... | L3 |
| pg-sqli-to-node | PostgreSQL SQLi to Node Compromise | Cross | WEB-07, DB-01, K8S-12, K8S-07 | CVE-2025-1094; N/A (misconfiguration); N/A (hostPath mount) | PG SQLi → DB RCE → hostPath → Kubelet | WEB-07 (PG SQLi) → BIG5 编码绕过 → SQL 注入 → 数据库读取 → DB-01 (PG Weak Auth RCE) → COPY PROGRAM → 系统命令执行 → K8S-12 (hostPath E... | L3 |
| php-to-mongo | PHP Deserialization to MongoDB NoSQL Injection | Web+DB | WEB-17, DB-09 | Insecure PHP deserialization; N/A (NoSQL injection) |  |  | L3 |
| privilege-to-etcd | Privilege to etcd | Kubernetes | K8S-11, K8S-06, K8S-08 | N/A (privileged pod); N/A (misconfiguration) | 特权容器逃逸 → RBAC → etcd | K8S-11 (Privileged Container) → nsenter 进入宿主机 namespace → 读宿主机 flag → K8S-06 (RBAC Abuse) → 从宿主机获取 kubeconfig, 读 secr... | L2 |
| rbcd-to-dcsync | RBCD to DCSync Domain Compromise | Active Directory | AD-17, S4U2Proxy, Domain Admin Access, AD-09 | ATT&CK T1558.003 (RBCD); ATT&CK T1003.006 | RBCD 接管计算机 → S4U → DCSync | lowpriv → Enumerate ACLs → RBCD on DESKTOP-HELPDESK$ → S4U2Proxy as Administrator → DA-level access → DCSync | L2 |
| redis-to-k8s | Redis to K8s Cluster Admin | Kubernetes | DB-05, K8S-11, K8S-06, K8S-08 | N/A (misconfiguration); N/A (privileged pod) | Redis 写 SSH → 特权 Pod → RBAC → etcd | DB-05 (Redis Unauthorized) → 未授权 Redis → 写 SSH key → 初始 shell → K8S-11 (Privileged Container) → nsenter 进入宿主机 → 读宿主机 ... | L3 |
| s3-to-kms | Cloud S3 Discovery to KMS Decryption | cloud+cloud+cloud+cloud | cloud-01, cloud-02, cloud-07, cloud-08 | （链内逻辑步骤，见组合场景 CVE） |  |  | L3 |
| sa-lateral-escape | SA Token Lateral to Escape | Cross | K8S-13, K8S-06, K8S-01 | N/A (RBAC lateral); N/A (misconfiguration); CVE-2024-21626 | 跨 ns SA Token → RBAC → runC 逃逸 | K8S-13 (SA Cross-Namespace) → ns-alpha 中发现泄露的 ns-beta token → 跨命名空间读取 → K8S-06 (RBAC Abuse) → 使用 token 在 ns-beta 中读 s... | L3 |
| seccomp-to-escape | hostPID Access to CRI Socket Escape | Kubernetes | K8S-23, K8S-16, Host Flag | N/A (misconfiguration); CRI socket abuse | hostPID 读宿主机 → CRI socket → 节点 flag | hostPID pod (locked down) → /proc/1/root → host filesystem → CRI socket → full node compromise | L2 |
| shadow-to-golden | Shadow Credentials to Golden Ticket | Active Directory | AD-18, NTLM Extraction, AD-09, AD-10 | ATT&CK T1606.002; ATT&CK T1003.006; ATT&CK T1558.001 | Shadow Credentials → DCSync → Golden Ticket | Shadow Credentials → PKINIT auth → NTLM extraction → DCSync → Golden Ticket | L3 |
| sqs-to-lambda | Cloud SQS Intercept to Lambda Command Injection | cloud+cloud+cloud+cloud | cloud-06, cloud-02, cloud-04, cloud-08 | （链内逻辑步骤，见组合场景 CVE） |  |  | L3 |
| ssrf-to-cloud | SSRF to Cloud Credential Theft | Web+cloud | WEB-10, cloud-03 | N/A (SSRF misconfiguration) |  | SSRF Internal Service Access → Probe internal cloud metadata → EC2 SSRF Localhost Flag Theft → Flag exfiltration | L2 |
| ssti-to-cloud | SSTI to Cloud Credential Theft | Web+cloud+cloud+cloud | WEB-12, cloud-02, cloud-07, cloud-08 | N/A (SSTI vulnerability) |  |  | L3 |
| tomcat-race-to-etcd | Tomcat Race Condition to etcd | Cross | WEB-02, LNX-05, K8S-06, K8S-08 | CVE-2024-50379; CVE-2025-32463; N/A (misconfiguration) | Tomcat 竞态 RCE → sudo 提权 → K8s 集群 | WEB-02 (Tomcat Race Condition) → PUT JSP + 条件竞争 → JSP 编译执行 → RCE → LNX-05 (Sudo Chroot) → CVE-2025-32463 → root → K8S... | L3 |
| tomcat-to-k8s | Tomcat Deserialization to K8s Admin | Cross | WEB-01, LNX-05, K8S-06, K8S-08 | CVE-2025-24813; CVE-2025-32463; N/A (misconfiguration) | Tomcat 反序列化 → sudo 提权 → K8s 集群 | WEB-01 (Tomcat 反序列化) → PUT 序列化 session → RCE → LNX-05 (Sudo Chroot) → CVE-2025-32463 → root → K8S-06 (RBAC Abuse) → S... | L3 |
| tomcat-to-rbcd | Tomcat Deserialization to RBCD Domain Admin | Cross (Web + Linux + AD) | WEB-01, LNX-05, Credential Discovery, AD Enumeration, AD-17, AD-09 | CVE-2025-24813; CVE-2025-32463; ATT&CK T1558.003 (RBCD); ATT&CK T1003.006 | Tomcat → Linux 提权 → AD 枚举 → RBCD → DCSync | Tomcat RCE → Linux PrivEsc → AD Credential Discovery → AD Enumeration → RBCD → DCSync | L3 |
| web-to-admin | Web to Domain Admin | Web+Linux+AD | WEB-03, LNX-06, AD-01, AD-09 | CVE-2025-34085; N/A (misconfiguration); ATT&CK T1558.003; ATT&CK T1003.006 |  | WordPress RCE → SUID Privilege Escalation → Kerberoasting → DCSync → Full domain compromise | L3 |
| wordpress-to-shadow | WordPress to Shadow Credentials Domain Admin | Cross (Web + DB + Linux + AD) | WEB-03, DB-02, LNX-05, Credential Discovery, AD-18, AD-09 | CVE-2025-34085; MySQL UDF Abuse; CVE-2025-32463; ATT&CK T1606.002; ATT&CK T1003.006 | WordPress → MySQL → Linux → Shadow Creds → DCSync | WordPress RCE → MySQL UDF → Linux Shell + PrivEsc → AD Credential Discovery → Shadow Credentials → DCSync | L3 |
| wp-lfi-to-cluster | WordPress LFI to Cluster Admin | Cross | WEB-06, K8S-06, K8S-01, K8S-08 | CVE-2025-0366; N/A (misconfiguration); CVE-2024-21626 | WordPress LFI RCE → RBAC → runC → etcd | WEB-06 (WordPress LFI) → Contributor 登录 → SVG 上传 → PHP LFI → RCE → K8S-06 (RBAC Abuse) → SA token → 读 secrets → K8S-0... | L3 |
| xss-to-cloud | Stored XSS Session Hijack to Cloud Takeover | Web+cloud+cloud+cloud | WEB-18, cloud-06, cloud-02, cloud-08 | Stored XSS |  |  | L3 |
| xxe-to-es | XXE SVG to Elasticsearch Data Exfiltration | Web+DB | WEB-14, DB-07 | XXE (XML External Entity); N/A (script injection) |  |  | L3 |

## 统计摘要

### 单点场景难度分布

| 难度 | 数量 |
|------|------|
| L1 | 24 |
| L2 | 63 |
| L3 | 14 |

### 攻击链难度分布

| 难度 | 数量 |
|------|------|
| L1 | 0 |
| L2 | 7 |
| L3 | 27 |

### 单点场景领域分布

| 领域 | 数量 |
|------|------|
| Web | 22 |
| Database | 9 |
| Linux | 9 |
| Kubernetes | 26 |
| Active Directory | 14 |
