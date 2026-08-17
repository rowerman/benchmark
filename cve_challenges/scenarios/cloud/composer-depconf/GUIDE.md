# CLOUD-37 CloudImposer：托管数据平台依赖混淆

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-37 |
| 名称 | CloudImposer: Dependency Confusion in Managed Data Platform |
| 技术/CVE | N/A (global namespace dependency confusion, case #270) |
| 难度 | L3 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10637 |

## 场景概述
托管数据平台（Composer 类）构建时按名字从全局命名空间解析私有包。
该名字没有预留机制：攻击者在全局注册同名同版本包，平台后续解析时
就会安装攻击者的代码，并在平台 worker 上执行。

## 教材锚点
- 案例：CloudImposer 依赖混淆（#270）；CDK bucket squatting（#230）
- 平面：控制面（包解析/构建）→ 失败边界：命名（全局命名空间）
- 六镜头：MAGIC（平台自动安装依赖并以平台身份执行）；SHARED（构建
  worker 是平台共享组件）

## 前置知识
- 依赖混淆（dependency confusion）原理：私有名在公共命名空间未被预留

## 利用步骤
1. 读取平台文档，找到被解析的私有包 `data-platform-utils==1.0.0`。
2. 在全局包注册表 PUT 同名同版本包，内容为恶意命令
   （`cat /app/flag.txt`）。
3. 触发平台 `/resolve`——平台 worker 执行恶意 setup 代码，
   输出平台 worker 上的 flag。

## Flag
`flag{cloud-37-platform-worker}`

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Package namespaces, dependency resolution, and managed pipelines |
| 侦察与前置条件 | Private package name and public registry precedence |
| 核心漏洞与利用 | Publish a dependency-confusion package under the private name |
| 权限、横向或影响 | Managed pipeline code execution |
| 验证 | Observe the pipeline execution or flag exfiltration |

## 修复建议
私有包名必须预留/签名；解析应校验包来源与哈希；构建 worker 不应
持有平台级敏感数据。
