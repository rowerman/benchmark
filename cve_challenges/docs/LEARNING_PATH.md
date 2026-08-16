# CVE Benchmark — Learning Path

## 难度分级

| 级别 | 描述 | 场景数 |
|:---:|------|:---:|
| **L1** | 单步或配置错误即可利用 | 11 |
| **L2** | 需约 2 步或中等技巧 | 51 |
| **L3** | 多步、跨组件或高技巧 | 20 |

---

## 推荐学习路径

### 路径1: Web渗透 (纯Docker, 无前置依赖)

```
WEB-03 (文件上传) → WEB-10 (SSRF基础) → WEB-11 (SSRF bypass)
→ WEB-13 (XXE基础) → WEB-14 (XXE SVG) → WEB-12 (SSTI)
→ WEB-15 (JWT) → WEB-16 (GraphQL) → WEB-17 (PHP反序列化)
→ WEB-18 (XSS) → WEB-07 (SQLi编码绕过)
```

### 路径2: 数据库攻击 (纯Docker)

```
DB-05 (Redis未授权) → DB-06 (MongoDB未授权) → DB-01 (PG弱口令)
→ DB-02 (MySQL UDF) → DB-09 (NoSQL注入) → DB-07 (ES脚本注入)
→ DB-08 (CouchDB RCE) → DB-03 (Oracle TNS) → DB-04 (MSSQL链接服务器)
```

### 路径3: 云渗透 (Docker+LocalStack, 需awscli)

```
CLOUD-01 (SSRF→IMDS) → CLOUD-06 (DB→IMDS) → CLOUD-04 (Lambda注入)
→ CLOUD-05 (CloudFormation注入) → CLOUD-11 (OIDC伪造) → CLOUD-12 (跨账号接管)
→ CLOUD-16 (日志缺口静默枚举)
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
xxe-to-es (Web→DB, 2步) → php-to-mongo (Web→DB, 2步)
→ redis-to-k8s (DB→K8s, 4步) → container-to-admin (K8s, 3步)
→ web-to-db-to-cross-account (Web→Cloud, 5步)
```

---

## 按ATT&CK战术分类

| 战术 | 场景 |
|------|------|
| **Initial Access** (TA0001) | WEB-03/04, DB-05/06, K8S-07, CLOUD-01 |
| **Execution** (TA0002) | WEB-12 (SSTI), DB-08 (CouchDB), K8S-10, CLOUD-04 |
| **Privilege Escalation** (TA0004) | WEB-08/09, DB-02, K8S-11/14/19 |
| **Credential Access** (TA0006) | CLOUD-01 (IMDS), DB-05 (SSH密钥), K8S-06 (Secret) |
| **Discovery** (TA0007) | WEB-16 (GraphQL), K8S-06/13, CLOUD-12 |
| **Lateral Movement** (TA0008) | DB-04 (Linked Server), K8S-07/16/17 |
| **Collection** (TA0009) | DB-01/02, CLOUD-01 (S3) |
| **Exfiltration** (TA0010) | CLOUD-16 (日志缺口静默枚举) |
| **Impact** (TA0040) | K8S-08/20 |

---

## 场景速查表

| ID | 名称 | 域 | 难度 | 端口 |
|----|------|----|:---:|:---:|
| WEB-03 | WordPress Simple File List RCE | Web | L1 | 10103 |
| WEB-10 | SSRF Internal Service Access | Web | L1 | 10110 |
| WEB-11 | SSRF Localhost Auth Bypass | Web | L2 | 10111 |
| WEB-12 | SSTI Jinja2 Template Injection | Web | L2 | 10112 |
| WEB-13 | XXE XML External Entity | Web | L1 | 10113 |
| WEB-14 | XXE SVG Upload | Web | L2 | 10114 |
| WEB-15 | JWT Algorithm None Attack | Web | L2 | 10115 |
| WEB-16 | GraphQL Introspection + IDOR | Web | L2 | 10116 |
| WEB-17 | PHP Deserialization Auth Bypass | Web | L2 | 10117 |
| WEB-18 | Stored XSS Session Theft | Web | L1 | 10118 |
| DB-05 | Redis Unauthorized Access | DB | L1 | 10205 |
| DB-06 | MongoDB Unauthorized Access | DB | L1 | 10206 |
| CLOUD-01 | SSRF to IMDS Credential Theft | Cloud | L2 | 10601 |
| CLOUD-04 | Lambda Code Injection → IAM PassRole | Cloud | L2 | 10604 |
| CLOUD-05 | CloudFormation Template Injection → SSM | Cloud | L2 | 10605 |
| CLOUD-06 | Managed DB COPY FROM PROGRAM → IMDS Access | Cloud | L2 | 10606 |
| CLOUD-11 | OIDC Claim Mismatch → Cross-Repo AssumeRole | Cloud | L2 | 10611 |
| CLOUD-12 | IAM Trust Policy Principal:* → Cross-Account Takeover | Cloud | L2 | 10612 |
| CLOUD-16 | CloudTrail Logging Gap → Silent Enumeration | Cloud | L2 | 10616 |
| K8S-06 | K8s RBAC Secrets Abuse | K8s | L1 | — |
| K8S-07 | Kubelet API Anonymous Access | K8s | L2 | — |
| K8S-10 | Helm v2 Tiller Unauthenticated | K8s | L1 | — |
| K8S-11 | Privileged Container Breakout | K8s | L2 | — |
| K8S-12 | hostPath Writable Mount Escape | K8s | L2 | — |
| K8S-13 | SA Token Cross-Namespace Lateral | K8s | L2 | — |
| K8S-16 | CRI Socket Mount Escape | K8s | L2 | — |
| K8S-17 | Docker Socket Mount Escape | K8s | L1 | — |
| K8S-01 | runC WORKDIR Container Escape | K8s | L2 | — |
| K8S-08 | etcd Unauthorized Access | K8s | L3 | — |
| K8S-20 | ingress-nginx Admission Controller RCE (IngressNightmare) | K8s | L3 | 10443 |
