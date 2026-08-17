# CLOUD-08 CI/CD 管道投毒 → 凭据外泄

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-08 |
| 名称 | CI/CD Pipeline Poisoning → Secret Exfiltration |
| 技术/CVE | N/A (CI/CD script injection) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10608 |

## 场景概述
攻击者可以向 CI 运行器提交恶意工作流/仓库内容，管道脚本存在 shell
执行注入。CI 环境携带仓库 Secret（flag），投毒后可在构建过程中
读取并外泄。

## 教材锚点
- 案例：托管 CI/CD 攻击面（Ch9）；CI 脚本注入
- 平面：控制面（CI）→ 失败边界：身份/供应链
- 六镜头：MAGIC（CI runner 以仓库身份自动执行）；SHARED（runner
  是共享构建舰队）

## 前置知识
- CI 工作流语法与脚本注入；CI Secret 环境

## 利用步骤
1. 向 git-server 提交恶意 workflow/脚本，触发 ci-runner 执行。
2. 在注入的 shell 命令中读取 CI 环境变量/Secret。
3. 拿到 pipeline flag。

## Flag
`flag{cloud-08-pipeline}`（runner 环境）

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Git/CI pipeline services and build execution |
| 侦察与前置条件 | Pipeline trigger, repository input, and runner environment discovery |
| 核心漏洞与利用 | Poison CI configuration or build commands |
| 权限、横向或影响 | CI runner secret exposure |
| 验证 | Read the runner-provided flag/secret |

## 修复建议
管道脚本参数化并禁止 shell 拼接；Secret 按最小权限注入；
PR 触发任务不得携带写权限。
