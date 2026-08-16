# CLOUD-05 CloudFormation 模板注入 → SSM 参数泄露

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
1. 提交 YAML 模板，其中 Fn::Sub 表达式内嵌 `${...}` 嵌套引用。
2. 观察解析器输出——利用 Fn::Sub 的求值顺序泄露 SSM 参数值。
3. 参数中包含 flag。

## Flag
`flag{cloud-05-default}`（解析器输出）

## 修复建议
模板表达式求值必须隔离；服务端解析不得接触高权限机密；对模板做
严格语法校验。
