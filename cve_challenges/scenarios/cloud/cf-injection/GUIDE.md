# CLOUD-05 CloudFormation 模板注入 → SSM 参数泄露

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-05 |
| 名称 | CloudFormation Template Injection → SSM |
| 技术/CVE | N/A (CF Fn::Sub injection) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10605 |

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
1. 通过控制台（localhost:10605）提交原始 YAML 模板，其中 `BucketName`
   使用 `!Sub ${/secure/flag}` 简写（等价于 `Fn::Sub` 字典）。
2. 控制台把模板原文发给解析器；解析器按 CloudFormation 内建函数求值，
   将 `${/secure/flag}` 替换为 SSM 参数值。
3. 观察解析器输出——泄露的 SSM 参数即为 flag。

> 注意：模板必须以 YAML 原文提交；若套上 JSON 包装，`Fn::Sub` 会退化成
> 普通字符串而不被求值。

## Flag
`flag{cloud-05-default}`（解析器输出）

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
