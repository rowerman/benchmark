# CLOUD-32 Entra Actor Token：身份 actor 校验缺陷

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-32 |
| 名称 | Entra Actor Token: Tenant-A Token Accepted by Tenant-B Directory |
| 技术/CVE | N/A (actor/tenant validation bug, case #246) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10632 |

## 场景概述
目录 API 只校验 JWT 签名，从不检查 token 声明的租户与被访问的租户
是否一致（actor/tenant 绑定缺失）。攻击者用自己租户（tenant-a）签发
的 token 直接访问 tenant-b 的目录，以"全局管理员"身份读到对方数据。

## 教材锚点
- 案例：Entra ID actor token 校验缺陷导致跨租户全局管理员（#246）
- 平面：控制面（身份）→ 失败边界：身份/账号
- 六镜头：IDENTITY（签名有效 ≠ 主体有权访问目标租户）；BOUNDARY（租户
  边界靠 claim 校验，而该校验缺失）

## 前置知识
- JWT 结构与签名验证；OAuth/Entra 的 tenant 绑定（issuer/audience/actor）

## 利用步骤
1. 从身份服务为 `tenant-a` 获取签名 token。
2. 携带该 token 请求 `GET /api/users?tenant=tenant-b`。
3. 服务端仅验签、不比对 token 租户，返回 tenant-b 的用户列表与 flag。

## Flag
`flag{cloud-32-tenant-b-admin}`

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Entra-style actor tokens, directory APIs, and tenant claims |
| 侦察与前置条件 | Actor/tenant claim handling across directory endpoints |
| 核心漏洞与利用 | Present a Tenant-A actor token to a Tenant-B operation |
| 权限、横向或影响 | Cross-tenant identity confusion |
| 验证 | Use the accepted token to retrieve the tenant flag |

## 修复建议
令牌校验必须同时验证 tenant/issuer/audience 与被访问资源一致；actor
与 subject 分离校验；跨租户访问一律默认拒绝。
