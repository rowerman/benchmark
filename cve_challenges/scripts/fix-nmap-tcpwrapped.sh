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
  10601   # prv-41 ssrf-to-imds
  10604   # prv-47 lambda-passrole
  10605   # prv-12 cf-injection
  10608   # prv-48 ci-poisoning
  10609   # prv-21 notebook-escape
  10611   # prv-49 oidc-federation
  10612   # prv-05 cross-account-trust
  10613   # prv-06 golden-saml
  10615   # prv-07 scp-bypass
  10621   # cloud-01 global-s3-squatting
  10623   # prv-50 cosmiss-notebook
  10624   # prv-33 rds-logfdw
  10625   # prv-34 cloudsql-index-rce
  10626   # prv-35 synlapse-ir
  10627   # prv-51 extrareplica-repl
  10628   # prv-23 wireserver-bootstrap
  10629   # prv-40 buildfleet-registry
  10630   # prv-25 pickle-model
  10631   # prv-52 attachme-volume
  10632   # prv-53 actor-token
  10633   # prv-54 omigod-agent
  10634   # prv-55 iam-enum-oracle
  10635   # prv-56 beta-endpoint
  10636   # prv-57 resource-explorer
  10637   # cloud-02 composer-depconf
  10638   # prv-36 lowcode-secrets
  10639   # prv-58 shared-nat
  10640   # prv-59 dataform-pt
  10641   # prv-60 serverless-sa
  10642   # prv-37 persistence-as-a-service
)

# ============================================================
# Cloud-service scenarios — internal service socat proxy ports
# ============================================================
CLOUD_PROXY_PORTS=(
  10670   # PRV-41 IMDS proxy
  10671   # PRV-41 S3 proxy
  10703   # OIDC IdP proxy
  10704   # S3 simulator proxy
  10705   # Lambda simulator proxy
  10706   # prv-21 k8s-api
  10707   # prv-49 IAM / prv-06 SAML IdP proxy (reused)
  10708   # prv-05 S3
  10709   # prv-06 IAM/STS
  10716   # prv-51 internal CA
  10718   # prv-40 internal registry
  10719   # prv-40 tenant puller
  10720   # prv-25 inference
  10721   # prv-25 cluster API
  10722   # prv-23 control-plane / prv-25 node IMDS (reused)
  10723   # prv-55 STS oracle
  10724   # prv-55 audit log
  10726   # cloud-02 package registry
)

# ============================================================
# Kubernetes scenarios - exposed registry/etcd ports
# ============================================================
K8S_PORTS=(
  11379   # prv-42 real etcd
  10500   # prv-38 registry
  10501   # prv-39 registry
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
