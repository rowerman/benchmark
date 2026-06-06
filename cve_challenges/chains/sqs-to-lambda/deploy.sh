#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[Chain-39] Cloud SQS Intercept to Lambda Command Injection — 4 steps, Pure Cloud"
echo "[*] Single shared LocalStack with combined init (SQS + IAM + Lambda + KMS)"

docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d --build 2>&1 | tail -2
echo "  [+] LocalStack (SQS+IAM+Lambda+KMS) at http://localhost:11639"

echo ""
echo "[Chain-39] Ready"
echo "  Step 1: SQS list queues → receive messages → flag{c39-step1-sqs}"
echo "  Step 2: IAM escalation → use creds from SQS message → flag{c39-step2-iam}"
echo "  Step 3: Lambda injection → aws lambda invoke process-order → flag{c39-step3-lambda}"
echo "  Step 4: KMS Decrypt → kms:Decrypt s3://secure-data/ → flag{c39-step4-kms}"
