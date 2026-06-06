#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[Chain-38] Cloud S3 Discovery to KMS Decryption — 4 steps, Pure Cloud"
echo "[*] Single shared LocalStack with combined init (S3 + IAM + STS + KMS)"

docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] LocalStack (S3+IAM+STS+KMS) at http://localhost:11638"

echo ""
echo "[Chain-38] Ready"
echo "  Step 1: S3 public bucket → aws s3 ls s3://flag-bucket/ --endpoint-url http://localhost:11638 --no-sign-request → flag{c38-step1-s3}"
echo "  Step 2: IAM escalation → use creds from credentials.txt → flag{c38-step2-iam}"
echo "  Step 3: STS AssumeRole → assume AdminRole → flag{c38-step3-sts}"
echo "  Step 4: KMS Decrypt → kms:Decrypt encrypted flag → flag{c38-step4-kms}"
