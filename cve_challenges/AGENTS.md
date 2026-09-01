# CVE Benchmark 项目说明

## 项目定位

本仓库是 DARWIN LLM Pentest Evaluation 使用的自托管渗透测试基准。它把公开 CVE、常见错误配置和云/Kubernetes 权限边界问题封装成可重复部署的靶场，用于评估 LLM 或人工测试者的侦察、漏洞利用、横向移动和影响验证能力。

当前注册表（`scripts/scenarios.yaml`）包含 89 个独立场景：57 个 Docker Compose 场景、32 个 KIND/Kubernetes 场景；`chains/` 另有 37 条多场景攻击链。场景中的 Flag 是每次启动时生成或注入的测试值，不应把 GUIDE 中的示例值当作运行时 Flag。

## 项目结构

```text
cve_challenges/
├── scenarios/                 # 可独立运行的单场景，GUIDE.md 是场景事实来源
│   ├── web/                   # Web 应用与 Web 漏洞
│   ├── db/                    # 数据库与数据库配置/注入问题
│   ├── cloud/                 # 公有云服务模拟场景（通常为 Docker Compose）
│   └── k8s/                   # KIND 集群、容器逃逸与 Kubernetes 配置场景
├── infra/cloud/               # 云场景共用的 OIDC、IMDS、IAM、审计等模拟器；不是独立注册场景
├── chains/                    # 多步骤攻击链；每个目录通常含 chain.yaml、deploy.sh、teardown.sh
│   └── _runtime/              # 云攻击链的共享部署运行时与 Chain Console
├── scripts/
│   ├── scenarios.yaml         # 场景注册表：稳定 ID、类型、路径、端口、难度、CVE/技术
│   ├── start-scenario.sh      # 单点场景唯一入口，生成单个或多个 Flag
│   ├── start-chain.sh         # 攻击链唯一入口，生成链级 Flag
│   ├── stop-chain.sh          # 停止并清理攻击链
│   ├── stop-scenario.sh       # 按注册表停止并清理单场景
│   ├── k8s-common.sh          # KIND 场景共享的集群、镜像、Flag、等待辅助函数
│   ├── validate-structure.py  # 注册表、GUIDE、端口和攻击链引用校验
│   ├── validate-flag-contract.py # 校验单点与攻击链 Flag 运行时注入
│   ├── check-cloud-consistency.py # 云场景 ID、路径和链引用一致性校验
│   ├── validate-all.sh        # 批量启动、可达性检查和停止
│   └── flag_manager.py / verify-flag.sh # Flag 生成和格式/蜜罐值校验
└── README.md
```

每个已注册场景必须位于注册表的 `path`，并包含非空 `GUIDE.md`。Docker 场景必须提供 `docker-compose.yml`/`.yaml`（部分 Kubernetes 场景还会带 registry compose）；Kubernetes 场景必须提供 `deploy.sh`，通常配套 `teardown.sh` 和 `kind-config.yaml`。新增或移动场景时，应同步修改注册表和 GUIDE，并运行结构校验。

## 启动方式

所有命令均从仓库根目录执行。主机需要 Bash、Python 3（含 `PyYAML`）、Docker Engine 及 Docker Compose v2；Kubernetes 场景还需要 `kind` 和 `kubectl`。部分场景首次部署会从互联网拉取基础镜像或 Calico/Ingress manifest。

### 查看和运行单场景

```bash
# 查看稳定 ID、类型、端口、难度和 CVE
./scripts/list-scenarios.sh

# 启动（脚本从 scenarios.yaml 查找路径/类型，生成随机 Flag）
./scripts/start-scenario.sh web-03

# 停止并清理
./scripts/stop-scenario.sh web-03
```

Docker 场景只能通过 `start-scenario.sh` 启动。单 Flag 场景使用 `CVE_FLAG`，多 Flag 场景使用连续的 `CVE_FLAG1`、`CVE_FLAG2`……；脚本将变量写入场景目录的 `.env`/`flag.txt`（如存在），然后执行 `docker compose up -d --build`。Compose 文件及 Dockerfile 必须引用这些变量；固定 Flag 只能作为 fallback，不得成为脚本启动时实际使用的值。多 Flag 场景的每一枚 Flag 都必须在 GUIDE 中说明位置，并在启动输出中单独打印。Kubernetes 场景同样由 `start-scenario.sh` 唯一启动，变量由对应 `deploy.sh` 消费。

攻击链只能通过 `start-chain.sh <chain-directory>` 启动，通过 `stop-chain.sh <chain-directory>` 清理。链级 Flag 使用连续的 `CVE_FLAG1`、`CVE_FLAG2`……，`CVE_FLAG` 是第一枚 Flag 的兼容别名。显式传入的变量优先，缺失变量才生成随机值。每个链步骤按 `chain.yaml` 中的 Flag 声明分配编号；runtime 部署器将该步骤的编号 Flag 映射为当前单点 Compose 部署的 `CVE_FLAG`、`CVE_FLAG1...N`。攻击链的 `deploy.sh`、Compose、Dockerfile 和 Kubernetes manifest 必须消费这些变量，固定值只能作为 fallback。
设置 `CHAIN_DRY_RUN=1` 可只验证链识别和 Flag 编号，不执行部署。

### 运行攻击链

```bash
# 攻击链唯一启动入口
./scripts/start-chain.sh managed-db-lateral

# 完成测试后统一清理
./scripts/stop-chain.sh managed-db-lateral
```

云攻击链通常调用 `chains/_runtime/deploy_chain.py`：它把链中 Docker 场景接入专用网络，只通过 Chain Console 暴露入口 `http://localhost:11600+链编号`，并用 `X-Chain-Key` 保护 `/artifacts/<key>`。部署脚本会打印实际端口、Chain Key 和各步骤提示；不要假设所有链都使用同一种运行时，Kubernetes/混合链应以各自 `deploy.sh` 的输出和 `chain.yaml` 为准。

### 验证与清理

```bash
python3 scripts/validate-structure.py
python3 scripts/check-cloud-consistency.py
python3 scripts/validate-flag-contract.py
bash scripts/validate-all.sh                 # 默认验证 Docker 场景
bash scripts/validate-all.sh k8s             # 仅验证 Kubernetes 场景
bash scripts/validate-all.sh all             # 验证全部非 optional 场景
./scripts/verify-flag.sh 'flag{captured-value}'
```

`validate-all.sh` 会逐个启动、等待并停止场景，Docker/KIND 资源可能占用较多时间和磁盘。需要清理遗留环境时可运行 `bash scripts/reset-all.sh`；该脚本会删除本基准的 Docker 容器、KIND 集群、网络和 Flag 目录，执行前确认没有其他任务依赖这些资源。
