# CLOUD-08 IAM 信任策略 Principal:* → 跨账号接管

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-08 |
| 名称 | IAM Trust Policy Principal:* → Cross-Account Takeover |
| 技术/CVE | N/A (overly permissive trust policy) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10612 |

## 场景概述
目标账号的 IAM 角色信任策略写了 `"Principal": "*"`（或过宽的
`AWS` 主体），任何账号都能 AssumeRole。攻击者枚举角色名后直接
跨账号接管，读取目标 S3 资源。

## 教材锚点
- 案例：跨账号信任滥用（#010 家族）
- 平面：控制面（IAM）→ 失败边界：账号/身份
- 六镜头：IDENTITY（信任主体过宽）；DETECTION（AssumeRole 成功
  在受害者侧不留痕）

## 前置知识
- IAM trust policy 主体语义；跨账号 AssumeRole；角色枚举

## 利用步骤
1. 枚举角色名：`GET /roles` 与 `GET /roles/<name>` 可查看脱敏后的
   信任策略（Principal 与 Condition 结构可见、具体账号被隐藏）。
2. 用攻击者身份的 AK/SK 调用 AssumeRole，目标为信任策略过宽的角色
   （如 `CrossAccountRole` 信任本账号 root，或 `AdminRole` 为
   `Principal:*`）。
3. 用返回的三段式临时凭据（AccessKeyId / SecretAccessKey /
   SessionToken）请求 S3 的 `/flag.txt`。S3 会向 IAM 校验会话有效性
   与角色权限；匿名、伪造或权限不足的凭据一律返回 403。

## Flag
`flag{cloud-08-...}`（S3 对象）

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | IAM trust policies and STS-style role assumption |
| 侦察与前置条件 | Role ARN discovery and Principal/trust condition inspection |
| 核心漏洞与利用 | Assume a role trusted by Principal:* |
| 权限、横向或影响 | Cross-account privilege takeover |
| 验证 | Use the assumed role to read the target flag |

## 修复建议
信任策略限定具体主体与条件；启用外部 ID / 条件键；监控异常 AssumeRole。
