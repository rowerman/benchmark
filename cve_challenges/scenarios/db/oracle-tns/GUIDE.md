# DB-03: Oracle TNS Poisoning

## 场景信息

| 字段 | 值 |
|---|---|
| ID | DB-03 |
| 名称 | Oracle TNS Poisoning |
| 技术/CVE | TNS Poisoning |
| 难度 | L3 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10203 |

## 场景概述
- 技术：TNS Poisoning
- 难度：L3
- 交付方式：docker
- 入口端口：10203
## 攻击路径与利用步骤

| Property | Value |
|----------|-------|
| Technique | TNS Poisoning |
| Difficulty | L3 |
| Port | 10203 |
| SID | XE |
| Credentials | system / password123 |

### Attack Path
```
TNS Listener poisoning → MITM → Capture DB credentials → Connect → UTL_FILE → /flag.txt
```

```bash
# TNS poisoning attack against Oracle listener on port 10203
# Use tnscmd or custom TNS packet injection
# Redirect client connection through attacker-controlled proxy
# Capture credentials, then connect:
sqlplus system/password123@localhost:10203/XE
SELECT * FROM flag_table;
# flag{db-03-xxxxxxxxxxxxxxxx}
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Oracle listener reached through a Docker Compose socat proxy |
| 侦察与前置条件 | TNS listener behavior, SID discovery, and client connection flow |
| 核心漏洞与利用 | Perform TNS listener poisoning/MITM and authenticate to Oracle |
| 权限、横向或影响 | Oracle database file access through UTL_FILE |
| 验证 | Connect with sqlplus and retrieve the flag value |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。

## Flag

完成上述利用后，读取场景返回的 `flag{...}` 值；可用 `scripts/verify-flag.sh` 验证捕获结果。
