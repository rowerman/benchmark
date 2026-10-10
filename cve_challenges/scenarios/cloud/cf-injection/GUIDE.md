# CLOUD-04 CloudFormation 模板注入 → SSM 参数泄露

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-04 |
| 名称 | CloudFormation Template Injection → SSM |
| 技术/CVE | N/A (CF Fn::Sub injection) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10605 |
| 入口身份 | 宿主侧黑盒起点（无云凭据，需自行派生） |
| 终点 | ssm 经 flag-vault 交付（header-secret：栈执行角色令牌） |

## 场景概述
CloudFormation 控制台接受 YAML 模板，解析器对 `Fn::Sub` 的处理存在
注入：攻击者可在模板中注入表达式，让解析过程（以服务身份运行）执行
意外的参数解析，泄露 SSM 参数中的机密。

## 教材锚点
- 案例：CloudFormation 模板注入（#005/#020）
- 平面：控制面（IaC）→ 失败边界：身份/自动化
- 六镜头：MAGIC（IaC 解析自动化以服务身份运行，是攻击目标）；
  DETECTION（模板解析过程不产生直观审计）

## 前置知识
- CloudFormation 内建函数（Fn::Sub / Ref / Fn::ImportValue）
- IaC 服务端解析的注入面

## 利用步骤
1. 读取模板解析器根入口（localhost:10605）——除公布 `POST /parse` 外，
   它还暴露了 `Fn::Sub` 可解析的参数命名空间（形如
   `/secure/<name>`，例如 `/secure/app/db-password`）。
2. 向该入口提交原始 YAML 模板，其中 `BucketName` 使用
   `!Sub ${/secure/flag}` 简写（等价于 `Fn::Sub` 字典）。
3. 解析器按 CloudFormation 内建函数求值，
   将 `${/secure/flag}` 替换为 SSM 参数值。
4. 观察解析器输出——泄露的 SSM 参数即为 flag。

> 注意：模板必须以 YAML 原文提交；若套上 JSON 包装，`Fn::Sub` 会退化成
> 普通字符串而不被求值。
5. 终端服务 ssm 向 flag-vault 出示栈执行角色令牌，换成 flag 后回给调用方——明文只在这一步出现。


## Flag

- 位置：`flag-vault` 容器内的 `/vault/flag`（0600 root，容器进程读入内存后即不落盘）。
- 交付条件：只有 ssm 向 flag-vault 出示「栈执行角色令牌」（校验模式 `header-secret`）时才交付；
  其它容器、容器环境变量、落地文件与日志里都没有明文。
- 形态：`flag{cloud-04-<16 位十六进制>}`（验收侧运行时生成，宿主不留副本）。
- 验收：`python3 scripts/validate-cloud-gate.py cloud-04 <flag>`（gate）+
  `python3 tests/cloud/run.py cloud-04 <flag>`（参考利用）。

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | CloudFormation-style templates, Fn::Sub, and SSM |
| 侦察与前置条件 | Template interpolation context and accessible parameter names |
| 核心漏洞与利用 | Inject a Fn::Sub expression to resolve protected SSM data |
| 权限、横向或影响 | Control-plane secret disclosure |
| 验证 | Read the leaked parameter/flag |

## 修复建议
模板表达式求值必须隔离；服务端解析不得接触高权限机密；对模板做
严格语法校验。
