# CLOUD-04 Lambda 代码注入 → IAM PassRole

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-04 |
| 名称 | Lambda Code Injection → IAM PassRole |
| 技术/CVE | N/A (command injection + IAM privesc) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10604 |

## 场景概述
API Gateway 把用户提交的代码原样转发给 Lambda 沙箱执行（命令注入）。
Lambda 执行环境携带 IAM 临时凭据；攻击者利用凭据进一步 AssumeRole，
完成服务侧提权。

## 教材锚点
- 案例：Serverless 执行面（Ch9）；IAM PassRole 提权路径
- 平面：数据面（函数执行）→ 控制面（IAM）；失败边界：身份
- 六镜头：MAGIC（托管函数执行即自动化以服务身份运行）；
  IDENTITY（函数环境注入角色凭据）

## 前置知识
- Serverless 执行模型；环境变量中的临时凭据；IAM AssumeRole

## 利用步骤
1. POST `/invoke`，`{"code": "import os; print(os.environ)"}` 读取
   Lambda 环境（或直接 `cat` 环境文件），拿到 IAM AK/SK。
2. 用凭据调用 IAM 服务（`_infra/iam-trust`）AssumeRole，换取目标角色。
3. 用角色凭据读取受保护资源得到 flag。

## Flag
`flag{cloud-04-step2-lambda}`（Lambda 环境）及跨账号 flag

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Serverless gateway, Lambda execution, and IAM |
| 侦察与前置条件 | Command-injection input and Lambda role permissions |
| 核心漏洞与利用 | Inject code/commands and request a function with PassRole |
| 权限、横向或影响 | IAM privilege escalation through a delegated execution role |
| 验证 | Invoke the created function or role path to obtain the flag |

## 修复建议
函数入口禁止任意代码执行；执行角色最小权限；运行时不注入可读凭据。
