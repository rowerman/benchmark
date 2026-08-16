# CLOUD-30 模型即代码：恶意 pickle → 推理 Pod → 节点 IMDS

## 场景概述
托管推理平台加载租户上传的 PyTorch/pickle 模型——"加载模型"就是执行
代码（pickle 反序列化会调用 `__reduce__`）。平台虽有 pickle 扫描器，
但只警告不拦截。恶意模型在推理 pod 内 RCE，接着访问节点 IMDS 窃取
节点 IAM 角色，最后用节点身份读取集群 Secret。

## 教材锚点
- 案例：Hugging Face gpt2 恶意 pickle（#091）；推理 pod 逃逸（Ch10）
- 平面：数据面（推理）→ 宿主/节点 → 失败边界：命名空间/身份
- 六镜头：MAGIC（托管推理是"运行你给的代码"这一产品本身）；
  DETECTION（扫描器是警告不是门禁）

## 前置知识
- Python pickle 反序列化（`__reduce__`）
- 节点 IMDS 与节点 IAM 角色；EKS 集群凭据

## 利用步骤
1. 构造 `__reduce__` 返回 `subprocess.check_output(cmd)` 的 pickle，
   命令为访问节点 IMDS 的 Python 代码。
2. 上传模型——注册表返回"dangerous pickle detected"，但**仍接受**。
3. 调用 `/infer` 触发加载，命令输出（节点角色名）作为推理结果返回。
4. 再上传一个窃取凭据的模型，拿到节点 AccessKey/SecretKey/Token。
5. 用节点 Token 调集群 `/secrets`，读到 Secret 与 flag。

## Flag
`flag{cloud-30-cluster-secrets}`

## 修复建议
推理平台应使用非 pickle 格式（safetensors）或隔离沙箱加载；扫描器
必须能拦截；推理 pod 不应能访问节点 IMDS。
