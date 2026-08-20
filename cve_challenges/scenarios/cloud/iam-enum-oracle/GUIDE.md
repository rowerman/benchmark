# CLOUD-25 IAM 枚举 2.0：无日志访问拒绝 oracle

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-25 |
| 名称 | IAM Enumeration 2.0: Unlogged AccessDenied Oracle |
| 技术/CVE | N/A (uncovered service error oracle, case #134/#137) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10634 |

## 场景概述
CloudTrail 并不覆盖所有服务：调用不支持的 API 不产生任何审计事件，
但 AccessDenied 错误仍会返回调用者的完整 ARN（身份枚举 oracle）。
同理，`sts:AssumeRole` 的错误信息在"角色存在但不可信"与"角色不存在"
之间有差异，可用作跨账号角色枚举的布尔 oracle——受害者的审计日志
全程为空。

## 教材锚点
- 案例：IAM enumeration 2.0（#134）；AssumeRole 角色枚举（#137）
- 平面：控制面（枚举）→ 失败边界：检测（no-event 层）
- 六镜头：DETECTION（无事件即不可见）；IDENTITY（错误信息泄露主体身份）

## 前置知识
- CloudTrail 覆盖范围与"无事件层"
- 错误差分 oracle（verbose error differential）

## 利用步骤
1. 用泄露的密钥调用未记录 API `/api/unsupported`——AccessDenied 返回
   完整 ARN，且审计日志无记录。
2. 对单词表逐个调用 `sts:AssumeRole`，比对错误信息差异，确认存在的角色
   （AdminRole / SecretRole / DataPipelineRole）。
3. 检查 `/logs`——审计记录数为 0，侦察完全不可见。

## Flag
`flag{cloud-25-zero-audit-enum}`

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | IAM APIs, AccessDenied responses, and STS role assumption |
| 侦察与前置条件 | Role/user candidate generation and response-difference analysis |
| 核心漏洞与利用 | Use an unlogged AccessDenied oracle to enumerate valid identities |
| 权限、横向或影响 | Stealthy identity reconnaissance and role targeting |
| 验证 | Assume/enumerate the discovered identity to obtain the flag |

## 修复建议
所有 API 都应被审计（含错误响应）；错误信息不得携带调用者 ARN；
AssumeRole 失败信息统一（feature-inherent oracle 需在设计上消除）。
