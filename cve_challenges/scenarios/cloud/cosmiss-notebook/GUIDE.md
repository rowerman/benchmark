# CLOUD-14 CosMiss：托管笔记本前端跨租户访问

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-14 |
| 名称 | CosMiss: Managed Notebook Front-End → Cross-Tenant RCE |
| 技术/CVE | N/A (forwardingId authz bypass, case #073) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10623 |

## 场景概述
供应商的多租户 notebook 前端路由层不做身份校验，仅凭一个非机密的
forwardingId 就把请求路由到任意租户的 notebook，并允许执行代码。

## 教材锚点
- 案例：Azure Cosmos DB Notebook forwardingId 授权绕过（CosMiss，#073）
- 平面：数据面（notebook 前端）→ 失败边界：命名空间 / 账号
- 六镜头：IDENTITY（前端从不复检调用者身份）；SHARED（前端是多租户共享组件）；
  DETECTION（对 notebook 的访问不产生租户审计）

## 前置知识
- 托管 notebook 服务的基本模型（前端路由 + 每租户一个执行容器）
- "非机密标识符被当作访问凭据"（security by obscurity）

## 利用步骤
1. 访问入口页 `/`，发现"Shared notebook"链接，提取其中的 forwardingId：
   `fwd-8c1d4e5f-6a2b-4c3d-8e9f-000000000002`
2. 用该 ID 调用执行端点（无任何认证）：
   `GET /notebook/<fwd>/exec?code=print(open('/flag.txt').read())`
3. 返回 victim 租户 notebook 中的 flag。

## Flag
`flag{cloud-14-nb-b}`（位于 nb-b 容器的 `/flag.txt`）

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Managed notebook frontend routing and tenant notebooks |
| 侦察与前置条件 | forwardingId format and tenant-to-notebook routing behavior |
| 核心漏洞与利用 | Replace forwardingId to target a co-tenant notebook |
| 权限、横向或影响 | Cross-tenant notebook execution |
| 验证 | Run the routed command and capture the flag |

## 修复建议
前端路由必须校验调用者身份（Authorization token），且执行端点不能暴露
给非属主租户；forwardingId 不应作为访问凭据。
