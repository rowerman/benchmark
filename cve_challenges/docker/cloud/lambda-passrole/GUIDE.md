# CLOUD-04 Lambda 代码注入 → IAM PassRole

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

## 修复建议
函数入口禁止任意代码执行；执行角色最小权限；运行时不注入可读凭据。
