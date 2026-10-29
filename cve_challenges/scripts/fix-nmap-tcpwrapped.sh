#!/bin/bash
# fix-nmap-tcpwrapped.sh
# 修复 Docker bridge + iptables NAT 导致的 nmap "tcpwrapped" 问题
# Docker 使用 iptables DNAT + conntrack 处理端口发布，会过滤 nmap 的服务探测包
# 此脚本在 DOCKER-USER chain 插入 ACCEPT 规则（Docker 重启后保留）
# 需要 root/sudo 权限执行
#
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "[!] This script requires root. Run with: sudo bash $0"
  exit 1
fi

echo "[*] Fixing nmap tcpwrapped for Docker-published ports..."

# ============================================================
# MSSQL scenarios — TDS 协议不发送明文 banner
# ============================================================
MSSQL_PORTS=(
  10119   # MSSQL xp_cmdshell (web/mssql-xp-cmdshell)
  10204   # MSSQL linked server low (db/mssql-linked-server)
  10214   # MSSQL linked server target (db/mssql-linked-server)
)

# ============================================================
# Oracle TNS — TNS Listener 在 Docker NAT 后可能被误判
# ============================================================
ORACLE_PORTS=(
  10203   # Oracle TNS (db/oracle-tns)
)

# ============================================================
# Cloud-service scenarios — public service ports (Docker -p published)
# ============================================================
CLOUD_WEB_PORTS=(
  10601   # k8s-04 ssrf-to-imds
  10604   # k8s-34 lambda-passrole
  10605   # k8s-35 cf-injection
  10608   # k8s-36 ci-poisoning
  10609   # k8s-37 notebook-escape
  10611   # k8s-38 oidc-federation
  10612   # k8s-39 cross-account-trust
  10613   # k8s-40 golden-saml
  10615   # k8s-41 scp-bypass
  10621   # cloud-01 global-s3-squatting
  10623   # k8s-42 cosmiss-notebook
  10624   # k8s-43 rds-logfdw
  10625   # k8s-44 cloudsql-index-rce
  10626   # k8s-45 synlapse-ir
  10627   # k8s-46 extrareplica-repl
  10628   # k8s-47 wireserver-bootstrap
  10629   # k8s-48 buildfleet-registry
  10630   # k8s-49 pickle-model
  10631   # k8s-50 attachme-volume
  10632   # k8s-51 actor-token
  10633   # k8s-52 omigod-agent
  10634   # k8s-53 iam-enum-oracle
  10635   # k8s-54 beta-endpoint
  10636   # k8s-55 resource-explorer
  10637   # cloud-02 composer-depconf
  10638   # k8s-56 lowcode-secrets
  10639   # k8s-57 shared-nat
  10640   # k8s-58 dataform-pt
  10641   # k8s-59 serverless-sa
  10642   # k8s-60 persistence-as-a-service
)

# ============================================================
# Cloud-service scenarios — internal service socat proxy ports
# ============================================================
CLOUD_PROXY_PORTS=(
  10670   # K8S-04 IMDS proxy
  10671   # K8S-04 S3 proxy
  10703   # OIDC IdP proxy
  10704   # S3 simulator proxy
  10705   # Lambda simulator proxy
  10706   # k8s-37 k8s-api
  10707   # k8s-38 IAM / k8s-40 SAML IdP proxy (reused)
  10708   # k8s-39 S3
  10709   # k8s-40 IAM/STS
  10716   # k8s-46 internal CA
  10718   # k8s-48 internal registry
  10719   # k8s-48 tenant puller
  10720   # k8s-49 inference
  10721   # k8s-49 cluster API
  10722   # k8s-47 control-plane / k8s-49 node IMDS (reused)
  10723   # k8s-53 STS oracle
  10724   # k8s-53 audit log
  10726   # cloud-02 package registry
)

# ============================================================
# Kubernetes scenarios - exposed registry/etcd ports
# ============================================================
K8S_PORTS=(
  11379   # k8s-08 real etcd
  10500   # k8s-09 registry
  10501   # k8s-15 registry
)

ALL_TCP_PORTS=("${MSSQL_PORTS[@]}" "${ORACLE_PORTS[@]}" "${CLOUD_WEB_PORTS[@]}" "${CLOUD_PROXY_PORTS[@]}" "${K8S_PORTS[@]}")

added=0
skipped=0

# ── TCP ports (MSSQL, Oracle, Cloud) ─────────────────────────────
for port in "${ALL_TCP_PORTS[@]}"; do
  if ! iptables -C DOCKER-USER -p tcp --dport "$port" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; then
    iptables -I DOCKER-USER 1 -p tcp --dport "$port" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
    echo "  + ACCEPT tcp/$port (conntrack: NEW,ESTABLISHED,RELATED)"
    ((added++))
  else
    ((skipped++))
  fi
done

echo ""
echo "[+] Done: $added rules added, $skipped already present"
echo ""
echo "    Verify with: sudo iptables -L DOCKER-USER -n -v"
echo "    Remove rules with: sudo iptables -F DOCKER-USER"
echo ""
echo "    Note: DOCKER-USER chain persists across Docker restarts."
echo "    These rules allow full nmap probe traffic to the listed ports,"
echo "    preventing the 'tcpwrapped' false positive in service detection."
