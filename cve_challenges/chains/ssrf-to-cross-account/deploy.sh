#!/bin/bash
set -euo pipefail
echo "[Chain-32] SSRF → IMDS → Cross-Account Takeover"
cd "$(dirname "$0")"
CVE_FLAG1="${CVE_FLAG1:-flag{c32-step1-ssrf\}}" \
CVE_FLAG2="${CVE_FLAG2:-flag{c32-step2-imds\}}" \
CVE_FLAG3="${CVE_FLAG3:-flag{c32-step3-cross\}}" \
CVE_FLAG4="${CVE_FLAG4:-flag{c32-step4-final\}}" \
docker compose up -d --build
echo "[+] Chain-32 Ready on port 11632"
echo "    Step 1: SSRF → http://169.254.169.254:5000/latest/meta-data/iam/security-credentials/ec2-role"
echo "    Step 2: Use IMDS creds on S3 → http://169.254.0.20:5000/files/flag.txt"
echo "    Step 3: AssumeRole via IAM Trust → http://localhost:11632"
echo "    Step 4: Cross-account access → final flag"
