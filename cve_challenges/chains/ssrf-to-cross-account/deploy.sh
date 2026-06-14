#!/bin/bash
set -euo pipefail
echo "[Chain-32] SSRF → IMDS → Cross-Account Takeover"
cd "$(dirname "$0")"
CVE_FLAG="flag{c32-step1-ssrf}" docker compose up -d --build
echo "[+] Chain-32 Ready on port 11632"
echo "    Step 1: SSRF → http://169.254.169.254:5000/latest/meta-data/iam/security-credentials/ec2-role"
echo "    Step 2: Use IMDS creds on S3 → http://169.254.0.20:5000/files/flag.txt"
echo "    Step 3: AssumeRole via IAM Trust → http://localhost:11632"
echo "    Step 4: Cross-account access → final flag"
