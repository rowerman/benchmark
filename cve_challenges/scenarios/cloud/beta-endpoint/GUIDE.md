# CLOUD-24 Service Catalog：非生产端点不可见写

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-24 |
| 名称 | Service Catalog Beta Endpoint: Invisible Write |
| 技术/CVE | N/A (non-production endpoint skips audit, case #154) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10635 |
| 辅助入口 | localhost:10727（console）；localhost:10729（production API）；localhost:10728（审计） |

## 场景概述
云控制台页面的 CSP 头泄露了非生产（beta/gamma）端点
`aws242-servicecatalog-beta`。该端点接受与生产相同的普通凭据，
执行真实的写操作，却完全不产生审计事件——"不可见变更"。

## 教材锚点
- 案例：Bypassing CloudTrail in AWS Service Catalog（#154）
- 平面：控制面（写操作）→ 失败边界：检测（日志路由）
- 六镜头：DETECTION（beta 端点绕过生产日志管线）；MAGIC（非生产
  基础设施与生产共享凭据）

## 前置知识
- 控制台 CSP 头可泄露内部端点；非生产环境的审计盲区

## 利用步骤
1. 读取控制台页面（`localhost:10727`）源码，从 CSP `connect-src` 中发现
   beta 端点 `aws242-servicecatalog-beta`；页面 bundle 同时泄露了生产
   端点使用的共享凭据（`X-Api-Key: valid-sigv4`）。
2. 用该凭据向 production 端点（`localhost:10729`）POST `/portfolios`
   建立基线——写入成功，并产生一条审计事件。
3. 用同一凭据向 beta 端点（入口 `localhost:10635`）POST `/portfolios`：
   创建成功，响应只返回 `portfolio_id`，且**不产生新的审计事件**。
4. 用同一凭据 `GET /portfolios/<portfolio_id>` 读取资源，获得 flag。
5. 查询 `localhost:10728/logs`：审计计数相比第 2 步没有增长，写操作完全
   不可见。

> 无凭据或错误凭据的请求返回 403——本场景刻画的是“审计盲区”而非
> “未鉴权接口”，因此调用者校验与生产端点保持一致。

## Flag
`flag{cloud-24-invisible-write}`

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Service catalog control plane, beta APIs, and audit logging |
| 侦察与前置条件 | Production/beta endpoint discovery and audit event comparison |
| 核心漏洞与利用 | Send a write through the non-production endpoint |
| 权限、横向或影响 | Unaudited control-plane state change |
| 验证 | Verify the hidden write/flag while confirming the audit blind spot |

## 修复建议
非生产端点必须走同一审计管线；CSP 不应暴露内部域名；beta 端点
不得接受生产凭据执行真实写操作。
