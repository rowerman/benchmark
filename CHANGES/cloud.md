# Cloud（公有云）场景变更记录

修改日期：2026-08-20

## 一、编号调整

- 2026-08-20 阶段曾将公有云场景由不连续编号 `CLOUD-01..42` 统一重编号为
  `CLOUD-01..33`；2026-08-22 将其中 02/03/12 迁移到 K8s 后，cloud 保留其余
  30 个 active ID，不再强制连续。
- 既有 cloud 场景沿用重编号后的目录；本次迁移的三个目录已从
  `scenarios/cloud/` 移至 `scenarios/k8s/`，映射关系：

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
- 新增一致性检查脚本 `scripts/check-cloud-consistency.py`，校验 30 个 active ID、链引用存在、GUIDE 与注册表一致，并拒绝已迁移的 02/03/12 引用。

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
- 本次同步 CLOUD-05/06/14/28 的控制面、身份和 flag 位置说明，并更新
  K8S-31/32/33 的 GUIDE 元数据、路径和部署入口。

## 五、验证情况

- 静态：`check-cloud-consistency.py`、`validate-structure.py`、Python 编译、全部 chain.yaml 解析、链脚本 Compose 引用存在性检查全部通过。
- Compose：30 个云场景（Docker 部署）`docker compose config` 通过；6 个变更 Compose 校验通过。
- 构建与冒烟：CLOUD-05/09/16/26/27 五个修改场景全部构建成功并端到端冒烟通过；`ssrf-to-cross-account` 链端到端验证通过。
- 清理：冒烟容器与卷已 `down -v`；`compileall` 生成的 `__pycache__` 已删除。


修改日期：2026-08-22

## 一、 修改内容

- `CLOUD-02/03/12` 已迁移为 `K8S-31/32/33`，cloud 注册表保留其余 30 个 ID，
  以避免现有 CLOUD 引用整体重编号。
- CLOUD-05 增加 SSM 参数 API、Stack 执行角色和资源解析输出；保留 `Fn::Sub`
  任意参数路径读取，并让未知伪参数维持原文字面行为。
- CLOUD-06 增加 CI workload token、短期身份材料和受保护云资源 API；CLOUD-14
  增加签名租户 token 与 notebook 控制面，保留 tenant/forwardingId 未绑定漏洞；
  CLOUD-28 增加托管 worker token 与跨租户资源 API。
- 移除多个 IAM proxy 的重复宿主端口 `10702`，避免云链组合启动冲突。
- 新增 `chains/_runtime` 公共编排器与 chain-console；20 条普通云链改为共享链网络、
  单一入口端口和 artifact API，Chain-32 保留专用 Compose 作为参考实现。
- 所有普通云链的 `chain.yaml` 增加 artifact 输入/输出格式和 runtime 合约，
  `deploy.sh`/`teardown.sh` 统一使用链级 project、共享网络和 `down -v`。

## 二、实施验证

- `validate-structure.py`：89 个场景、37 条链、60 个 Compose 文件通过；新增链运行时
  console/artifact 合约校验。
- `check-cloud-consistency.py`：30 个 active cloud 场景、迁移 ID 排除和链引用校验通过。
- 全部 20 条普通云链通过 runtime dry-run，确认每一步场景均有 Compose 部署且生成唯一
  `11600 + chain number` 入口；全部场景 Compose 配置解析通过。
- chain-console artifact PUT/GET smoke 通过；修改后的 Python 文件编译通过。
- 当前环境 Docker daemon 无权限，未执行实际镜像构建、容器启动或 K8s KIND 运行验收。

## 三、未完成事项

- 未对全部 Docker 场景逐一执行 build/up/down；当前完成的是 Compose 配置解析和重点场景的静态/局部 smoke。
- 未完成 21 条云链的容器级端到端 exploit-to-flag 验收。
- runtime 已提供 artifact API，但各攻击器尚未全部自动消费 `CHAIN_BUS_URL`，部分链仍需控制台交接。
- CLOUD-27 仍使用模拟调用者 header，未实现真实 SigV4；IAM `/validate` 仍是内存态且未做资源 ARN 级授权。