# CLOUD-26 CloudImposer：托管数据平台依赖混淆

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-26 |
| 名称 | CloudImposer: Dependency Confusion in Managed Data Platform |
| 技术/CVE | N/A (global namespace dependency confusion, case #270) |
| 难度 | L3 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10637 |
| 入口身份 | 宿主侧黑盒起点（无云凭据，需自行派生） |
| 终点 | victim-resource 经 flag-vault 交付（header-secret：平台工作负载令牌） |

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
2. 在全局包注册表 PUT 同名同版本包，内容为恶意命令，读取托管 worker 的 service-account token。
3. 触发平台 `/resolve`——恶意 setup 代码携带 worker 身份访问 tenant-b 资源 API，输出跨租户 Secret 与 flag。
4. 终端服务 victim-resource 向 flag-vault 出示平台工作负载令牌，换成 flag 后回给调用方——明文只在这一步出现。


## Flag

- 位置：`flag-vault` 容器内的 `/vault/flag`（0600 root，容器进程读入内存后即不落盘）。
- 交付条件：只有 victim-resource 向 flag-vault 出示「平台工作负载令牌」（校验模式 `header-secret`）时才交付；
  其它容器、容器环境变量、落地文件与日志里都没有明文。
- 形态：`flag{cloud-26-<16 位十六进制>}`（验收侧运行时生成，宿主不留副本）。
- 验收：`python3 scripts/validate-cloud-gate.py cloud-26 <flag>`（gate）+
  `python3 tests/cloud/run.py cloud-26 <flag>`（参考利用）。

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
