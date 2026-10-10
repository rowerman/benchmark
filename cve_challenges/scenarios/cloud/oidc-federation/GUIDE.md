# CLOUD-07 OIDC Claim 错配 → 跨仓库 AssumeRole

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-07 |
| 名称 | OIDC Claim Mismatch → Cross-Repo AssumeRole |
| 技术/CVE | N/A (OIDC federation misconfiguration) |
| 难度 | L3 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10611 |
| 入口身份 | 宿主侧黑盒起点（无云凭据，需自行派生） |
| 终点 | iam 经 flag-vault 交付（jwt：OIDC 的 RS256 令牌（含 iss/aud/sub）） |

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
4. 终端服务 iam 向 flag-vault 出示OIDC 的 RS256 令牌（含 iss/aud/sub），换成 flag 后回给调用方——明文只在这一步出现。


## Flag

- 位置：`flag-vault` 容器内的 `/vault/flag`（0600 root，容器进程读入内存后即不落盘）。
- 交付条件：只有 iam 向 flag-vault 出示「OIDC 的 RS256 令牌（含 iss/aud/sub）」（校验模式 `jwt`）时才交付；
  其它容器、容器环境变量、落地文件与日志里都没有明文。
- 形态：`flag{cloud-07-<16 位十六进制>}`（验收侧运行时生成，宿主不留副本）。
- 验收：`python3 scripts/validate-cloud-gate.py cloud-07 <flag>`（gate）+
  `python3 tests/cloud/run.py cloud-07 <flag>`（参考利用）。

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
