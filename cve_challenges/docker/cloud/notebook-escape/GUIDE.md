# CLOUD-09 AI Notebook 逃逸 → K8s SA Token 窃取

## 场景概述
托管 AI notebook 可执行任意代码（产品特性），但沙箱存在逃逸路径
（如 Docker socket 暴露）。攻击者从 notebook 逃逸到宿主/集群侧，
读取 K8s ServiceAccount token，访问集群 API。

## 教材锚点
- 案例：托管 notebook 攻击面（Ch10 Technique 2）；SageMaker/AI Hub（#011/#035）
- 平面：数据面（notebook）→ 集群；失败边界：命名空间/宿主
- 六镜头：MAGIC（notebook 执行即产品功能）；IDENTITY（SA token
  随容器自动挂载）

## 前置知识
- Notebook 代码执行；Docker socket 逃逸；SA token 与 K8s API

## 利用步骤
1. 在 notebook 中执行代码，探测 Docker socket（`/var/run/docker.sock`）。
2. 利用 socket 创建特权容器/挂载宿主路径，逃逸到节点。
3. 读取 `/var/run/secrets/kubernetes.io/serviceaccount/token`，调用
   K8s API 读取 Secret/flag。

## Flag
`flag{cloud-09-step2-...}`（集群 Secret）

## 修复建议
notebook 沙箱禁用 Docker socket；SA 最小权限；执行环境与集群隔离。
