# Cloud（公有云）场景变更记录

修改日期：2026-08-20

## 一、编号调整

- 公有云场景由不连续编号 `CLOUD-01..42` 统一重编号为连续 `CLOUD-01..33`。
- 目录名保持不变（仅逻辑 ID 迁移），映射关系：

| 旧编号 | 新编号 | 旧编号 | 新编号 | 旧编号 | 新编号 |
|---|---|---|---|---|---|
| 01 | 01 | 13 | 10 | 28 | 19 |
| 02 | 02 | 15 | 11 | 29 | 20 |
| 03 | 03 | 19 | 12 | 30 | 21 |
| 04 | 04 | 21 | 13 | 31 | 22 |
| 05 | 05 | 23 | 14 | 32 | 23 |
| 08 | 06 | 24 | 15 | 33 | 24 |
| 09 | 07 | 25 | 16 | 34 | 25 |
| 11 | 08 | 26 | 17 | 35 | 26 |
| 12 | 09 | 27 | 18 | 36 | 27 |
| 37 | 28 | 40 | 31 | — | — |
| 38 | 29 | 41 | 32 | — | — |
| 39 | 30 | 42 | 33 | — | — |

- 同步更新：`scripts/scenarios.yaml`、全部 `chain.yaml`、`deploy.sh`/`teardown.sh`、各场景 GUIDE、默认 flag 中的云场景 ID。
- 新增一致性检查脚本 `scripts/check-cloud-consistency.py`，校验编号唯一且覆盖 01–33、链引用存在、GUIDE 与注册表一致、无 34–42 残留。

## 二、单点场景修复

### CLOUD-05 CloudFormation 模板注入

- 控制台改为向解析器提交原始 YAML（原实现套 JSON 包装，导致 `Fn::Sub` 退化为普通字符串）。
- 修正 `PARSER_URL` 多余的 `/parse` 后缀（原请求打到 `/parse/parse` 返回 404）。
- 解析器注册 `!Sub/!Ref/!Join/!ImportValue` YAML 简写标签，与 CloudFormation 语法一致。

### CLOUD-09 跨账号信任

- IAM 模拟器新增会话注册表与 `POST /validate` 接口，校验 AccessKeyId/SecretAccessKey/SessionToken、角色权限与过期时间。
- S3 `/flag.txt` 改为强制调用 `/validate`，匿名、伪造或权限不足的凭据返回 403。
- S3 客户端改用标准库 `urllib`（原镜像未安装 `requests` 导致容器崩溃）。

### CLOUD-16 托管数据库逃逸

- 因 PostgreSQL 16 禁止降级 initdb 引导超级用户，改为双角色引导：`cloudsqladmin` 为引导超级用户，`cloudsqluser` 为普通客户角色并持有 public schema。
- 客户角色不再具备超级用户权限，直接 `COPY ... FROM PROGRAM` 被数据库拒绝。
- 控制台受控模拟“属主变更为供应商角色→ANALYZE 由供应商连接重估索引函数”，完整漏洞链可读取宿主 flag。

### CLOUD-26 Service Catalog Beta 端点

- beta/prod API 增加模拟签名凭据校验（`X-Api-Key`），无凭据请求返回 403。
- beta 写操作不再直接在 create 响应中返回 flag；需用同一凭据读取资源后才获得 flag。
- beta 写不产生审计，prod 写产生审计（验证：beta 后审计数 0，prod 后审计数 1）。

### CLOUD-27 Resource Explorer

- 资源详情接口 `/resources/<rid>` 增加调用者上下文校验（`X-Caller-ARN`），缺失时返回 403。
- 搜索仍保持“不产生审计”特征，且只返回资源元数据（不含 secret）。

## 三、攻击链修复

- 全部链 `deploy.sh`/`teardown.sh` 的 Compose 相对路径由错误的 `../scenarios` 修正为 `../../scenarios`。
- 修复 `ssrf-to-oidc/teardown.sh` 指向不存在目录的引用。
- 旗舰链 `ssrf-to-cross-account`：修正 step2 S3 的 `FLAG` 环境变量、新增校验会话凭据的 `s3-cross` 服务、attacker 改用 `S3_URL`，实现 SSRF→IMDS→S3→AssumeRole→跨账号 S3 的端到端串通。

## 四、文档同步

- 重编号阶段全局更新了 GUIDE 标题/ID；本次补充同步了五个修改场景的利用步骤：
  - CLOUD-05：原始 YAML 提交与 `!Sub` 简写说明。
  - CLOUD-09：三段式临时凭据与 S3 会话校验说明。
  - CLOUD-16：新增“客户角色非超级用户、直接命令执行被拒”边界说明。
  - CLOUD-26：修正“create 直接返回 flag”的过时描述，改为读取资源后取 flag。
  - CLOUD-27：补充读取详情需调用者上下文。

## 五、验证情况

- 静态：`check-cloud-consistency.py`、`validate-structure.py`、Python 编译、全部 chain.yaml 解析、链脚本 Compose 引用存在性检查全部通过。
- Compose：30 个云场景（Docker 部署）`docker compose config` 通过；6 个变更 Compose 校验通过。
- 构建与冒烟：CLOUD-05/09/16/26/27 五个修改场景全部构建成功并端到端冒烟通过；`ssrf-to-cross-account` 链端到端验证通过。
- 清理：冒烟容器与卷已 `down -v`；`compileall` 生成的 `__pycache__` 已删除。

## 六、未完成事项

- 未对全部 33 个云场景逐一执行 build/up/down（仅修改过的 5 个场景完整验证；未修改场景只做 Compose 配置与 ID 一致性校验）。
- 其余 5 条重点链（managed-db-lateral、managed-data-lateral、ci-to-oidc、detection-blindspot、supply-chain-persistence）未做端到端漏洞验收；多数链由独立 Compose 项目组成，缺少共享网络与凭据传递通道，链间状态传递仍依赖手工/脚本。
- CLOUD-02/03/12（KIND/K8s 部署）未做运行时验证。
- CLOUD-27 的调用者上下文仍是模拟 header，未实现真实 SigV4 签名链路。
- IAM `/validate` 按角色名返回权限列表，未实现资源 ARN 级权限判断；会话为容器内存态，重启后失效。
