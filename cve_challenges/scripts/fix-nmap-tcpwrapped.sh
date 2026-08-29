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
# Cloud scenarios — attacker-facing web ports (Docker -p published)
# ============================================================
CLOUD_WEB_PORTS=(
  10601   # cloud-01 ssrf-to-imds
  10604   # cloud-03 lambda-passrole
  10605   # cloud-04 cf-injection
  10608   # cloud-05 ci-poisoning
  10609   # cloud-06 notebook-escape
  10611   # cloud-07 oidc-federation
  10612   # cloud-08 cross-account-trust
  10613   # cloud-09 golden-saml
  10615   # cloud-10 scp-bypass
  10621   # cloud-11 global-s3-squatting
  10623   # cloud-12 cosmiss-notebook
  10624   # cloud-13 rds-logfdw
  10625   # cloud-14 cloudsql-index-rce
  10626   # cloud-15 synlapse-ir
  10627   # cloud-16 extrareplica-repl
  10628   # cloud-17 wireserver-bootstrap
  10629   # cloud-18 buildfleet-registry
  10630   # cloud-19 pickle-model
  10631   # cloud-20 attachme-volume
  10632   # cloud-21 actor-token
  10633   # cloud-22 omigod-agent
  10634   # cloud-23 iam-enum-oracle
  10635   # cloud-24 beta-endpoint
  10636   # cloud-25 resource-explorer
  10637   # cloud-26 composer-depconf
  10638   # cloud-27 lowcode-secrets
  10639   # cloud-28 shared-nat
  10640   # cloud-29 dataform-pt
  10641   # cloud-30 serverless-sa
  10642   # cloud-31 persistence-as-a-service
)

# ============================================================
# Cloud scenarios — internal service socat proxy ports
# ============================================================
CLOUD_PROXY_PORTS=(
  10701   # IMDS proxy
  10702   # IAM/STS proxy
  10703   # OIDC IdP proxy
  10704   # S3 simulator proxy
  10705   # Lambda simulator proxy
  10706   # PostgreSQL proxy
  10707   # SAML IdP proxy
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
