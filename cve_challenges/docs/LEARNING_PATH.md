# CVE Benchmark — Learning Path

## 难度分级

| 级别 | 描述 | 场景数 |
|:---:|------|:---:|
| **L1** | 单一漏洞利用，提供基础工具和入口 | 25+ |
| **L2** | 需要多步骤、技术组合或绕过防御 | 60+ |
| **L3** | 复杂利用链、内核逃逸、多服务协调 | 15+ |

---

## 推荐学习路径

### 路径1: Web渗透 (纯Docker, 无前置依赖)

```
WEB-03 (文件上传) → WEB-10 (SSRF基础) → WEB-11 (SSRF bypass)
→ WEB-13 (XXE基础) → WEB-14 (XXE SVG) → WEB-12 (SSTI) 
→ WEB-15 (JWT) → WEB-16 (GraphQL) → WEB-17 (PHP反序列化) 
→ WEB-18 (XSS) → WEB-07 (SQLi编码绕过)
```

### 路径2: Linux提权 (纯Docker, 需SSH客户端)

```
LNX-06 (SUID find) → LNX-07 (SUID vim) → LNX-13 (writable passwd)
→ LNX-09 (Capabilities) → LNX-10 (Cron) → LNX-12 (LD_PRELOAD)
→ LNX-11 (Polkit CVE) → LNX-05 (sudo chroot) → LNX-08 (Docker socket)
```

### 路径3: 云渗透 (纯Docker+LocalStack, 需awscli)

```
CLOUD-01 (S3公开读) → CLOUD-05 (DynamoDB注入) → CLOUD-06 (SQS拦截)
→ CLOUD-02 (IAM提权) → CLOUD-04 (Lambda注入) → CLOUD-07 (STS AssumeRole)
→ CLOUD-03 (SSRF→IMDS) → CLOUD-08 (KMS Oracle)
```

### 路径4: Kubernetes安全 (需KIND+kubectl)

```
K8S-06 (RBAC secrets) → K8S-07 (kubelet unauth) → K8S-10 (Helm Tiller)
→ K8S-11 (privileged pod) → K8S-12 (hostPath) → K8S-13 (SA cross-NS)
→ K8S-17 (Docker socket) → K8S-16 (CRI socket) → K8S-01 (runC escape)
→ K8S-08 (etcd unauth) → K8S-20 (ingress RCE)
```

### 路径5: 攻击链 (混合环境)

```
Chain-32 (SSRF→Cloud, 2步, 入门)
→ Chain-30 (Web→Linux→AD, 4步, 进阶)
→ Chain-31 (DB→Linux→K8s, 4步, 高级)
```

---

## 按ATT&CK战术分类

| 战术 | 场景 |
|------|------|
| **Initial Access** (TA0001) | WEB-03/04, K8S-07, DB-05/06 |
| **Execution** (TA0002) | WEB-12 (SSTI), CLOUD-04 (Lambda), K8S-10 |
| **Persistence** (TA0003) | LNX-10 (Cron), AD-18 (Shadow Creds) |
| **Privilege Escalation** (TA0004) | LNX-06~13, K8S-11/14, AD-05/09 |
| **Defense Evasion** (TA0005) | DEF-01~05 |
| **Credential Access** (TA0006) | AD-01/02/10, NET-01, CLOUD-03 |
| **Discovery** (TA0007) | K8S-06/13, AD-15, WEB-16 (GraphQL) |
| **Lateral Movement** (TA0008) | AD-05/16/21, DB-04, LNX-08 |
| **Collection** (TA0009) | DB-01/02, S3 (CLOUD-01) |
| **Exfiltration** (TA0010) | NET-02 (DNS exfil) |
| **Impact** (TA0040) | K8S-08/20, AD-09 |

---

## 场景速查表

| ID | 名称 | 域 | 难度 | 端口 | 关键词 |
|----|------|----|:---:|:---:|------|
| WEB-03 | WordPress File List RCE | Web | L1 | 10103 | 文件上传 |
| WEB-10 | SSRF Internal Access | Web | L1 | 10110 | SSRF, Docker网络 |
| WEB-11 | SSRF Localhost Bypass | Web | L2 | 10111 | SSRF, localhost绕过 |
| WEB-12 | SSTI Jinja2 | Web | L2 | 10112 | 模板注入, Python |
| WEB-13 | XXE XML Entity | Web | L1 | 10113 | XML, 外部实体 |
| WEB-14 | XXE SVG Upload | Web | L2 | 10114 | SVG, 文件上传 |
| WEB-15 | JWT alg:none | Web | L2 | 10115 | JWT, token伪造 |
| WEB-16 | GraphQL IDOR | Web | L2 | 10116 | GraphQL, 自省 |
| WEB-17 | PHP Deserialization | Web | L2 | 10117 | PHP, 对象注入 |
| WEB-18 | Stored XSS | Web | L1 | 10118 | XSS, Cookie窃取 |
| LNX-06 | SUID find | Linux | L1 | 10301 | SUID, GTFOBins |
| LNX-07 | SUID vim | Linux | L1 | 10302 | SUID, vim脚本 |
| LNX-08 | Docker Socket | Linux | L2 | 10303 | 容器逃逸 |
| LNX-09 | CAP_DAC_READ_SEARCH | Linux | L2 | 10304 | Capability |
| LNX-10 | Cron Hijacking | Linux | L2 | 10305 | 定时任务 |
| LNX-11 | Polkit CVE-2021-4034 | Linux | L2 | 10307 | pkexec |
| LNX-12 | LD_PRELOAD | Linux | L2 | 10308 | 共享库注入 |
| LNX-13 | Writable passwd | Linux | L1 | 10309 | 文件权限 |
| CLOUD-01 | S3 Public Read | Cloud | L1 | 10601 | AWS S3, ACL |
| CLOUD-02 | IAM CreatePolicy | Cloud | L2 | 10602 | AWS IAM, 提权 |
| CLOUD-03 | SSRF→IMDS | Cloud | L2 | 10603 | AWS EC2, 元数据 |
| CLOUD-04 | Lambda Injection | Cloud | L2 | 10604 | AWS Lambda, 无服务器 |
| K8S-06 | RBAC Secrets | K8s | L1 | — | RBAC, Secret |
| K8S-11 | Privileged Breakout | K8s | L2 | — | 特权容器 |
| K8S-20 | IngressNightmare | K8s | L3 | 10443 | Admission webhook |
| AD-01 | Kerberoasting | AD | L1 | — | TGS, 离线破解 |
| AD-09 | DCSync | AD | L2 | — | 域控同步 |
| DEF-01 | WAF Bypass SQLi | Defense | L2 | 10801 | WAF绕过 |
| NET-01 | ARP Sniffing | Network | L2 | 10901 | 包嗅探 |
| CI-01 | Pipeline Poisoning | CI/CD | L2 | 10701 | CI/CD, PPE |
