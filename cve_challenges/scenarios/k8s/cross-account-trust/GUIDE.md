# K8S-05 IAM 信任策略 Principal:* → 跨项目接管

## 场景信息

| 字段 | 值 |
|---|---|
| ID | K8S-05 |
| 名称 | IAM Trust Policy Principal:* → Cross-Project Takeover |
| 技术/CVE | N/A (overly permissive trust policy) |
| 难度 | L2 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10612 |
| 入口身份 | 宿主侧黑盒起点（无私有云凭据，需自行派生） |
| 终点 | private-object-store 经 flag-vault 交付（session-creds：AssumeRole 得到的三段式临时凭据） |

## 场景概述
私有云目标项目的 IAM 角色信任策略使用 `"Principal": "*"` 或过宽主体。
攻击者枚举角色后从其他项目直接 AssumeRole，读取目标对象的受保护资源。

## 教材锚点
- 案例：跨账号信任滥用（#010 家族）
- 平面：控制面（IAM）→ 失败边界：账号/身份
- 六镜头：IDENTITY（信任主体过宽）；DETECTION（AssumeRole 成功
  在受害者侧不留痕）

## 前置知识
- IAM trust policy 主体语义；跨项目 AssumeRole；角色枚举

## 利用步骤
1. 枚举角色名：`GET /roles` 与 `GET /roles/<name>` 可查看脱敏后的
   信任策略（Principal 与 Condition 结构可见、具体项目被隐藏）。
2. 用攻击者身份的 AK/SK 调用 AssumeRole，目标为信任策略过宽的角色
   （如 `CrossAccountRole` 信任本账号 root，或 `AdminRole` 为
   `Principal:*`）。
3. 用返回的三段式临时凭据（AccessKeyId / SecretAccessKey /
   SessionToken）请求私有对象存储（S3-compatible）的 `/flag.txt`。存储服务会向 IAM 校验会话有效性
   与角色权限；匿名、伪造或权限不足的凭据一律返回 403。
4. 终端服务 s3 向 flag-vault 出示AssumeRole 得到的三段式临时凭据，换成 flag 后回给调用方——明文只在这一步出现。


## Flag

- 位置：`flag-vault` 容器内的 `/vault/flag`（0600 root，容器进程读入内存后即不落盘）。
- 交付条件：只有 s3 向 flag-vault 出示「AssumeRole 得到的三段式临时凭据」（校验模式 `session-creds`）时才交付；
  其它容器、容器环境变量、落地文件与日志里都没有明文。
- 形态：`flag{k8s-05-<16 位十六进制>}`（验收侧运行时生成，宿主不留副本）。
- 验收：`python3 scripts/validate-cloud-gate.py k8s-05 <flag>`（gate）+
  `python3 tests/cloud/run.py k8s-05 <flag>`（参考利用）。

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | IAM trust policies and STS-style role assumption |
| 侦察与前置条件 | Role ARN discovery and Principal/trust condition inspection |
| 核心漏洞与利用 | Assume a role trusted by Principal:* |
| 权限、横向或影响 | Cross-project privilege takeover |
| 验证 | Use the assumed role to read the target flag |

## 修复建议
信任策略限定具体主体与条件；启用外部 ID / 条件键；监控异常 AssumeRole。
