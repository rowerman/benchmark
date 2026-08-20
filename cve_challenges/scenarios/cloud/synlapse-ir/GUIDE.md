# CLOUD-17 SynLapse：共享集成运行时跨租户凭据

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-17 |
| 名称 | SynLapse: Shared Integration Runtime → Co-Tenant Credentials |
| 技术/CVE | N/A (ODBC driver injection, CVE-2022-29972 lineage, case #062) |
| 难度 | L3 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10626 |

## 场景概述
分析平台把管道执行放到共享的多租户集成运行时（AutoResolveIntegrationRuntime）。
捆绑的 Redshift ODBC 驱动的 SAML 插件对 LOGIN_URL 做 shell 拼接，且"运行时选择"
只发生在客户端：攻击者把 runtime 名换成共享池后，注入的命令在多租户 worker 上
以 SYSTEM 执行，内存里躺着其他租户的凭据。

## 教材锚点
- 案例：SynLapse / CVE-2022-29972（#062）
- 平面：数据面 worker → 失败边界：命名空间（共享池）
- 六镜头：SHARED（共享 IR 是爆炸半径）；MAGIC（捆绑驱动的便利即攻击面）；
  DETECTION（客户看不到 worker 内部执行）

## 前置知识
- 集成运行时 / ETL worker 模型；ODBC 连接字符串注入
- "运行时归属只由客户端声明"（服务端不校验）

## 利用步骤
1. 查看控制面文档，确认存在共享运行时
   `AutoResolveIntegrationRuntime`。
2. 构造恶意连接字符串，`LOGIN_URL` 内放 shell 命令
   （本场景简化：`{echo x; cat /app/memory.json}`）。
3. 以 `runtime_name=AutoResolveIntegrationRuntime` 提交管道。
4. 共享 worker 执行注入命令，返回同机 co-tenant 凭据与 flag。

## Flag
`flag{cloud-17-co-tenant}`

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Data integration control plane, shared runtime, and ODBC |
| 侦察与前置条件 | Runtime selection and connection-string handling |
| 核心漏洞与利用 | Send an ODBC driver/LOGIN_URL injection to the shared runtime |
| 权限、横向或影响 | Co-tenant credential disclosure from shared execution |
| 验证 | Read the shared runtime result/flag |

## 修复建议
IR 节点必须专用、临时、单租户（修复后架构）；捆绑驱动的连接字符串
参数必须白名单过滤；worker 内存不得驻留跨租户凭据；管理凭据应短时效。
