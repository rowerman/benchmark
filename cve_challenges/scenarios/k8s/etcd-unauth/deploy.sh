#!/bin/bash
set -euo pipefail
K8S_ID="k8s-08"
CLUSTER_NAME="cve-k8s-08-etcd"
source "$(dirname "$0")/../../scripts/k8s-common.sh"

k8s_init
k8s_create_cluster
k8s_wait_ready

# Create a separate non-TLS etcd container (KIND etcd uses mTLS; this is the real target)
echo "[*] Starting standalone non-TLS etcd on port 11379..."
docker rm -f cve-etcd-flag 2>/dev/null || true
docker run -d --name cve-etcd-flag \
  --network kind \
  -p 11379:2379 \
  quay.io/coreos/etcd:v3.5.12 \
  /usr/local/bin/etcd \
    --listen-client-urls=http://0.0.0.0:2379 \
    --advertise-client-urls=http://0.0.0.0:2379

# Wait for etcd to be ready
echo "[*] Waiting for etcd to be ready..."
for i in $(seq 1 20); do
  if ETCDCTL_API=3 etcdctl --endpoints=http://localhost:11379 endpoint health 2>/dev/null; then
    break
  fi
  sleep 2
done

# Write the flag into the non-TLS etcd (simulating leaked K8s secrets data)
ETCDCTL_API=3 etcdctl --endpoints=http://localhost:11379 put /flag "$FLAG"
# Also create a K8s-secret-like key structure for realism
ETCDCTL_API=3 etcdctl --endpoints=http://localhost:11379 put /registry/secrets/kube-system/etcd-flag "$FLAG"

k8s_info
echo "[+] Standalone etcd at localhost:11379 (HTTP, no TLS, no auth)"
echo "[+] Attack: ETCDCTL_API=3 etcdctl --endpoints=http://localhost:11379 get / --prefix --keys-only"
echo "[+] Read flag: ETCDCTL_API=3 etcdctl --endpoints=http://localhost:11379 get /flag"
