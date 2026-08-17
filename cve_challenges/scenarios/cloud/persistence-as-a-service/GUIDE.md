# CLOUD-42 持久化即服务：托管自动化后门

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-42 |
| 名称 | Persistence-as-a-Service: Managed Automation Backdoor |
| 技术/CVE | N/A (automation-runbook persistence, case #149) |
| 难度 | L3 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10642 |

## 场景概述
攻击者在托管自动化服务注册一个恶意 runbook，脚本以服务身份周期性
从凭据库拉取当前凭据并访问受保护资源。防御方轮换凭据后，runbook
自动重新获取新凭据——持久化访问不依赖任何静态后门（Persistence-
as-a-service）。

## 教材锚点
- 案例：Cloud attacker persistence techniques in AWS（#149）
- 平面：控制面（自动化服务）→ 失败边界：检测/持久化
- 六镜头：MAGIC（托管自动化以服务身份周期运行）；DETECTION（runbook
  混在正常自动化中难以发现）

## 前置知识
- 托管自动化（runbook/定时任务）与托管身份
- 凭据轮换作为检测/清除手段的局限

## 利用步骤
1. 注册恶意 runbook：脚本内容=拉取当前 vault 凭据 → 调用受保护资源
   → 把凭据与 flag 外发到攻击者收集端点。
2. 触发凭据轮换（`POST /rotate`）并同步受保护资源的新密钥。
3. 等待 runbook 下一轮执行（每 5s）——它自动用新凭据再次读到 flag。

## Flag
`flag{cloud-42-persistence}`

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Managed automation, runbooks, credentials, and rotation |
| 侦察与前置条件 | Runbook persistence behavior and credential-vault access after rotation |
| 核心漏洞与利用 | Create a persistent automation runbook/backdoor |
| 权限、横向或影响 | Long-lived access across credential rotation |
| 验证 | Wait for or invoke the runbook and capture the final flag |

## 修复建议
自动化服务要审计 runbook 的来源与内容；托管身份按用途最小化；
轮换之外还要监控异常的周期外发行为；runbook 代码应受代码审查
与签名保护。
