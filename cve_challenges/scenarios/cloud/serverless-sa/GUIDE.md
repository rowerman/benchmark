# CLOUD-32 无服务器默认服务账号提权

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-32 |
| 名称 | Serverless Default Service Account: Platform Identity Escalation |
| 技术/CVE | N/A (over-scoped default SA, case #266/#272) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10641 |

## 场景概述
无服务器平台用"默认计算服务账号"运行函数，该账号权限过宽（可读
其他项目的资源）。攻击者部署恶意函数，函数运行时继承平台默认身份，
直接调用受害者项目 API 读取其 Secret。

## 教材锚点
- 案例：ImageRunner（#266）；GCP Cloud Functions 提权（#272）
- 平面：控制面（平台身份）→ 失败边界：身份
- 六镜头：IDENTITY（默认 SA 过宽且平台自动注入）；MAGIC（函数执行
  即自动化以服务身份运行）

## 前置知识
- 无服务器运行时身份（默认服务账号）与最小权限

## 利用步骤
1. 部署恶意函数，代码读取运行环境中的 `DEFAULT_SA_TOKEN`。
2. 函数输出默认服务账号令牌。
3. 用该令牌调用受害者项目 `/api/projects/victim/secrets`，
   读到 Secret 与 flag。

## Flag
`flag{cloud-32-victim-project}`

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Serverless functions, default ServiceAccounts, and project IAM |
| 侦察与前置条件 | Default service account scopes and invoker/deployer permissions |
| 核心漏洞与利用 | Invoke or deploy through an over-scoped default identity |
| 权限、横向或影响 | Platform identity privilege escalation |
| 验证 | Use the service account authority to retrieve the flag |

## 修复建议
默认服务账号必须最小权限并按函数隔离；禁止平台自动注入过宽身份；
项目间访问默认拒绝。
