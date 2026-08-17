# 下一 Session 待办（运行态回归）

更新日期：2026-08-17

本文件是临时交接记录。仓库根目录原有的 SESSION_SUMMARY.md 属于此前云场景扩充工作的交接，不要删除或覆盖。

## 当前结论

尚不能宣称 89 个单点场景均可构建、启动并通过利用路径获得 flag。

- 总场景：89；Docker 类型 57；Kubernetes 类型 32。
- Docker 首轮构建：46/57 成功。
- 对 46 个可构建 Docker 场景的启动检查：43 个登记入口端口可达。
- 29 个可启动 Docker 云场景的通用公开攻击入口测试：12 个返回真实 flag；其余需要按 GUIDE 给出的特定请求体、SQL 或多阶段参数逐条验证。
- 当前没有遗留 benchmark Docker 容器。

## 本 Session 已完成

### 文档与校验

- 89 个单点场景的 GUIDE.md 都有 场景信息 和五维 此场景利用了哪些知识 表。
- cve_challenges/scripts/validate-structure.py 会校验 GUIDE 元数据、知识表、Compose 构建上下文和登记端口。
- scenarios.yaml 中 18 个含 # 的 CVE/案例锚点已加引号，避免 YAML 注释截断。

### 已修复并运行复测

- scenarios/db/oracle-tns
  - 删除 ORACLE_DATABASE: XEPDB1，修复重复创建默认 PDB 导致的 Oracle 退出。
  - socat 改为 bridge 网络加 10203:10203 映射。
  - 已验证 localhost:10203 可达。
- scenarios/db/mssql-linked-server
  - socat 改为 bridge 网络加 10204:10204、10214:10214 映射。
  - 已验证两个端口可达。
- scenarios/web/mssql-xp-cmdshell
  - 新增 Program.cs 和 Web.csproj，恢复真实 ASP.NET SQLi Web 服务。
  - 新增 flag.txt，修正 Dockerfile、Compose 和 GUIDE 的 Linux cat /flag.txt 命令。
  - 已验证：SQLi -> 启用 xp_cmdshell -> 读取 flag。

## 待修复：构建前失败

1. cloud-09 (scenarios/cloud/notebook-escape)
   - notebook/Dockerfile 中 COPY workspace/ /app/workspace/，但 workspace/ 不存在。
   - 需要决定：补齐预期工作区内容，或删除不再使用的 COPY/相关功能；必须以 GUIDE 的 notebook escape 行为为准。

2. web-07 (scenarios/web/postgres-sqli)
   - Compose 指向缺失的 Dockerfile.db。
   - 需要检查原本 intended 的 PostgreSQL 初始化/构建流程，修正 Compose 引用或补回 Dockerfile。

## 待重试：Docker Hub 拉取失败

首轮失败是 Docker Hub token 请求连接被远端关闭，不是 Compose 语法错误。用户计划手动拉取：

~~~powershell
docker pull ubuntu:22.04
docker pull mongo:7.0
docker pull elasticsearch:8.11.0
docker pull couchdb:3.3.3
docker pull tomcat:9.0.98-jdk11
docker pull tomcat:9.0.97-jdk11
docker pull php:8.2-apache
~~~

重试受影响的 9 个 Docker 场景：

db-05, db-06, db-07, db-08, db-09, web-01, web-02, web-08, web-17。

## 待做：全量 exploit-to-flag 回归

不要使用现有 scripts/validate-all.sh 作为验旗依据：它只做启动/端口检查，端口不可达时甚至可能报告 PASS (files exist)。

需要为每个场景按 GUIDE 执行利用步骤，再从响应或客户端输出中提取 flag。已在通用云攻击入口调用中取得 flag 的场景：

cloud-27, cloud-28, cloud-30, cloud-32, cloud-34, cloud-35, cloud-36, cloud-37, cloud-38, cloud-39, cloud-40, cloud-41。

注意：cloud-32 返回的 flag{cloud-32-tenant-b-admin} 会被 scripts/verify-flag.sh 的 honeypot 规则因包含 admin 错误拒绝。需要修复验旗规则，或调整该场景的 flag 值。

其余 17 个已启动云场景的通用 POST 未拿到 flag，不应直接判为场景失败；需按照各自 GUIDE 的参数和多阶段步骤验证。

Web/DB 场景尚未做全量实际利用验证，除 WEB-09 外仅做过构建和入口可达性检查。

## Kubernetes 前置条件

- 当前系统未安装 kind，32 个 Kubernetes 类型场景尚未运行。
- kind 会自动拉取节点镜像；网络不稳定时可预拉取：

~~~powershell
docker pull kindest/node:v1.27.3
docker pull kindest/node:v1.28.12
~~~

- 安装 kind 后，逐场景运行 deploy.sh、执行 GUIDE 利用步骤、验证 flag，并运行 teardown.sh 清理。

## 建议继续顺序

1. 确认手动镜像拉取完成，重试 9 个 Docker 构建与启动。
2. 修复 cloud-09、web-07，做构建、启动和实际攻击路径复测。
3. 处理 verify-flag.sh 对 cloud-32 合法 flag 的误报。
4. 为剩余 Docker 场景逐个完成 exploit-to-flag 验证。
5. 安装 kind，完成 32 个 Kubernetes 场景的部署与 exploit-to-flag 验证。

## 已通过的基础检查

- python cve_challenges/scripts/validate-structure.py
- 102 个 Python 文件语法编译
- 58 份 Compose 配置解析
- git diff --check
