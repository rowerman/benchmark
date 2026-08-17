# CLOUD-11 OIDC Claim 错配 → 跨仓库 AssumeRole

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-11 |
| 名称 | OIDC Claim Mismatch → Cross-Repo AssumeRole |
| 技术/CVE | N/A (OIDC federation misconfiguration) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10611 |

## 场景概述
IAM 的 OIDC 联合信任策略缺少/放宽了 claim 条件（如仓库名、环境、
ref），攻击者可以伪造或利用其他仓库的 OIDC token 通过信任策略，
以 AssumeRoleWithWebIdentity 获得角色凭据。

## 教材锚点
- 案例：OIDC 缺条件信任（Ch3 T1，GitHub OIDC any-repo 假设）
- 平面：控制面（身份联合）→ 失败边界：身份
- 六镜头：IDENTITY（信任策略未复检 claim）；BOUNDARY（账号间信任
  被错误扩大）

## 前置知识
- OIDC federation；AssumeRoleWithWebIdentity；trust policy 条件

## 利用步骤
1. 阅读 OIDC IdP 文档，了解 claim 结构（iss/sub/aud）。
2. 发现信任策略只校验 issuer 不校验 sub/仓库条件。
3. 伪造/借用合法签发的 JWT（含目标角色 sub），调用 AssumeRoleWithWebIdentity
   获得角色凭据与 flag。

## Flag
`flag{cloud-11-...}`（角色凭据换取的资源）

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | OIDC issuer, JWT claims, and IAM role federation |
| 侦察与前置条件 | Issuer/audience/subject claim validation and trust policy inspection |
| 核心漏洞与利用 | Forge or reuse a token with a mismatched repository claim |
| 权限、横向或影响 | Cross-repository role assumption |
| 验证 | Assume the target role and retrieve the flag |

## 修复建议
信任策略必须限定 sub/aud/ref 等条件；对 OIDC token 做完整校验。
