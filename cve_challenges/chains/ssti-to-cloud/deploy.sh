#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo "[Chain-33] SSTI to Cloud Credential Theft — 4 steps, Web→Cloud×3"

# Step 1: SSTI Jinja2 (Docker)
echo "=== Step 1: WEB-12 SSTI Jinja2 ==="
docker compose -f "$ROOT/docker/web/ssti-jinja2/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] SSTI web app at http://localhost:10112"

# Step 2: IAM Privilege Escalation (LocalStack)
echo "=== Step 2: CLOUD-02 IAM Privilege Escalation ==="
docker compose -f "$ROOT/docker/cloud/iam-privesc/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] LocalStack (IAM) at http://localhost:10602"

# Step 3: STS AssumeRole (LocalStack)
echo "=== Step 3: CLOUD-07 STS AssumeRole ==="
docker compose -f "$ROOT/docker/cloud/sts-assumerole/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] LocalStack (STS) at http://localhost:10607"

# Step 4: KMS Decrypt (LocalStack)
echo "=== Step 4: CLOUD-08 KMS Decryption Oracle ==="
docker compose -f "$ROOT/docker/cloud/kms-oracle/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] LocalStack (KMS) at http://localhost:10608"

echo ""
echo "[Chain-33] Ready"
echo "  Step 1: http://localhost:10112 → SSTI RCE → flag{c33-step1-ssti}"
echo "  Step 2: http://localhost:10602 → IAM escalation → flag{c33-step2-iam}"
echo "  Step 3: http://localhost:10607 → STS AssumeRole → flag{c33-step3-sts}"
echo "  Step 4: http://localhost:10608 → KMS Decrypt → flag{c33-step4-kms}"
