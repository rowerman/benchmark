# PRV-21 托管笔记本逃逸 → 集群服务账号令牌窃取

## 场景信息

| 字段 | 值 |
|---|---|
| ID | PRV-21 |
| 名称 | Managed Notebook Escape → Cluster ServiceAccount Token Theft |
| 技术/CVE | N/A (notebook escape + SA token) |
| 难度 | L3 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10609 |
| 入口身份 | 宿主侧黑盒起点（无私有云凭据，需自行派生） |
| 终点 | flag-vault 容器内 /vault/flag（经宿主机容器层直接读取） |

## 场景概述
私有云 MLOps 平台允许租户在托管 notebook 中执行任意代码，但执行沙箱暴露了 Docker socket。
攻击者从 notebook 逃逸到宿主或集群侧，取得集群服务账号身份并读取受保护资源。

## 教材锚点
- 案例：托管 notebook 攻击面（Ch10 Technique 2）；SageMaker/AI Hub（#011/#035）
- 平面：数据面（notebook）→ 集群；失败边界：命名空间/宿主
- 六镜头：MAGIC（notebook 执行即产品功能）；IDENTITY（SA token
  随容器自动挂载）

## 前置知识
- Notebook 代码执行；Docker socket 逃逸；SA token 与 K8s API

## 利用步骤

1. 在 notebook 里执行代码，探测挂载进来的 `/var/run/docker.sock`。
2. 用这个 socket 与宿主机的 docker daemon 对话（`GET /containers/json`），列出租户之外的容器。
3. 找到 `flag-vault` 容器，经 `POST /containers/<id>/exec` + `POST /exec/<id>/start` 以 root 执行
   `cat /vault/flag`。
4. 密文只存在于该容器内的 0600 root 文件里，宿主机与其它容器都拿不到——读到它即证明已完成
   容器逃逸。

## Flag
`flag{prv-21-step2-...}`（集群 Secret）

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Managed notebook, shell execution, and Kubernetes ServiceAccounts |
| 侦察与前置条件 | Notebook execution context and mounted token location |
| 核心漏洞与利用 | Escape the notebook execution boundary |
| 权限、横向或影响 | Kubernetes ServiceAccount credential theft |
| 验证 | Read the token/flag from the notebook container |

## 修复建议
notebook 沙箱禁用 Docker socket；SA 最小权限；执行环境与集群隔离。
