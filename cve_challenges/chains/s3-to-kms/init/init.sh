#!/bin/bash
set -e

# Wait for LocalStack to be healthy
until curl -s http://localhost:4566/_localstack/health | grep -q '"iam"'; do
  sleep 2
done

echo "=== Chain-38 Combined Init: S3 → IAM → STS → KMS ==="

# ──────────────────────────────────────────────
# Step 1: S3 Public Bucket (CLOUD-01)
# ──────────────────────────────────────────────
aws --endpoint-url=http://localhost:4566 s3 mb s3://flag-bucket
aws --endpoint-url=http://localhost:4566 s3api put-bucket-acl --bucket flag-bucket --acl public-read
echo "flag{c38-step1-s3}" > /tmp/step1.txt
aws --endpoint-url=http://localhost:4566 s3 cp /tmp/step1.txt s3://flag-bucket/flag.txt

# ──────────────────────────────────────────────
# Step 2: IAM Escalation (CLOUD-02)
# ──────────────────────────────────────────────
aws --endpoint-url=http://localhost:4566 iam create-user --user-name lowpriv
LOWPRIV_KEYS=$(aws --endpoint-url=http://localhost:4566 iam create-access-key --user-name lowpriv)
LOWPRIV_KEY=$(echo "$LOWPRIV_KEYS" | jq -r '.AccessKey.AccessKeyId')
LOWPRIV_SECRET=$(echo "$LOWPRIV_KEYS" | jq -r '.AccessKey.SecretAccessKey')

aws --endpoint-url=http://localhost:4566 iam put-user-policy \
  --user-name lowpriv --policy-name IamEscalation \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Allow",
      "Action":["iam:CreatePolicy","iam:AttachUserPolicy","iam:GetUser","iam:ListUsers","iam:ListAttachedUserPolicies","iam:GetPolicy","iam:ListRoles","iam:GetRole","sts:AssumeRole"],
      "Resource":"*"
    }]
  }'

# Place lowpriv credentials in public S3 bucket (attacker discovers them via Step 1)
echo "{\"AWS_ACCESS_KEY_ID\":\"$LOWPRIV_KEY\",\"AWS_SECRET_ACCESS_KEY\":\"$LOWPRIV_SECRET\"}" > /tmp/creds.txt
aws --endpoint-url=http://localhost:4566 s3 cp /tmp/creds.txt s3://flag-bucket/credentials.txt

# Admin user + admin-secrets bucket
aws --endpoint-url=http://localhost:4566 iam create-user --user-name admin
ADMIN_KEYS=$(aws --endpoint-url=http://localhost:4566 iam create-access-key --user-name admin)
ADMIN_KEY=$(echo "$ADMIN_KEYS" | jq -r '.AccessKey.AccessKeyId')
ADMIN_SECRET=$(echo "$ADMIN_KEYS" | jq -r '.AccessKey.SecretAccessKey')

aws --endpoint-url=http://localhost:4566 iam attach-user-policy \
  --user-name admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

aws --endpoint-url=http://localhost:4566 s3 mb s3://admin-secrets

aws --endpoint-url=http://localhost:4566 s3api put-bucket-policy \
  --bucket admin-secrets \
  --policy "{
    \"Version\":\"2012-10-17\",
    \"Statement\":[{
      \"Effect\":\"Deny\",
      \"Principal\":\"*\",
      \"Action\":\"s3:GetObject\",
      \"Resource\":\"arn:aws:s3:::admin-secrets/*\",
      \"Condition\":{\"StringNotEquals\":{\"aws:username\":\"admin\"}}
    }]
  }"

export AWS_ACCESS_KEY_ID="$ADMIN_KEY"
export AWS_SECRET_ACCESS_KEY="$ADMIN_SECRET"
echo "flag{c38-step2-iam}" > /tmp/step2.txt
aws --endpoint-url=http://localhost:4566 s3 cp /tmp/step2.txt s3://admin-secrets/flag.txt
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

# ──────────────────────────────────────────────
# Step 3: STS AssumeRole (CLOUD-07)
# ──────────────────────────────────────────────
ROLE_ARN=$(aws --endpoint-url=http://localhost:4566 iam create-role \
  --role-name AdminRole \
  --assume-role-policy-document '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Allow",
      "Principal":{"AWS":"*"},
      "Action":"sts:AssumeRole"
    }]
  }' \
  --query 'Role.Arn' --output text)

aws --endpoint-url=http://localhost:4566 iam attach-role-policy \
  --role-name AdminRole --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

aws --endpoint-url=http://localhost:4566 s3 mb s3://flag-vault

aws --endpoint-url=http://localhost:4566 s3api put-bucket-policy \
  --bucket flag-vault \
  --policy "{
    \"Version\":\"2012-10-17\",
    \"Statement\":[{
      \"Effect\":\"Deny\",
      \"Principal\":\"*\",
      \"Action\":\"s3:GetObject\",
      \"Resource\":\"arn:aws:s3:::flag-vault/*\",
      \"Condition\":{\"StringNotEquals\":{\"aws:PrincipalArn\":\"$ROLE_ARN\"}}
    }]
  }"

export AWS_ACCESS_KEY_ID="$ADMIN_KEY"
export AWS_SECRET_ACCESS_KEY="$ADMIN_SECRET"
echo "flag{c38-step3-sts}" > /tmp/step3.txt
aws --endpoint-url=http://localhost:4566 s3 cp /tmp/step3.txt s3://flag-vault/flag.txt
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

# ──────────────────────────────────────────────
# Step 4: KMS Decryption Oracle (CLOUD-08)
# ──────────────────────────────────────────────
KEY_ID=$(aws --endpoint-url=http://localhost:4566 kms create-key \
  --description "Flag encryption key" \
  --key-usage ENCRYPT_DECRYPT \
  --query 'KeyMetadata.KeyId' --output text)

aws --endpoint-url=http://localhost:4566 s3 mb s3://secure-data

echo -n "flag{c38-step4-kms}" > /tmp/final.txt
CIPHERTEXT_B64=$(aws --endpoint-url=http://localhost:4566 kms encrypt \
  --key-id "$KEY_ID" \
  --plaintext fileb:///tmp/final.txt \
  --query CiphertextBlob --output text)
echo "$CIPHERTEXT_B64" | base64 -d > /tmp/encrypted.bin
aws --endpoint-url=http://localhost:4566 s3 cp /tmp/encrypted.bin s3://secure-data/encrypted_flag.bin
echo "{\"key_id\":\"$KEY_ID\",\"algorithm\":\"SYMMETRIC_DEFAULT\"}" > /tmp/meta.json
aws --endpoint-url=http://localhost:4566 s3 cp /tmp/meta.json s3://secure-data/metadata.json

# Cleanup temp files
rm -f /tmp/step1.txt /tmp/step2.txt /tmp/step3.txt /tmp/final.txt /tmp/creds.txt /tmp/encrypted.bin /tmp/meta.json

echo ""
echo "=============================================="
echo "Chain-38: S3 → IAM → STS → KMS"
echo "=============================================="
echo ""
echo "Step 1 — S3 Public Read (no auth needed):"
echo "  aws s3 ls s3://flag-bucket/ --endpoint-url http://localhost:11638 --no-sign-request"
echo "  aws s3 cp s3://flag-bucket/credentials.txt /tmp/creds.txt --endpoint-url http://localhost:11638 --no-sign-request"
echo ""
echo "Step 2 — IAM Privilege Escalation:"
echo "  Low-priv user can escalate via iam:CreatePolicy + iam:AttachUserPolicy"
echo "  Username: lowpriv"
echo "  Flag in: s3://admin-secrets/flag.txt (requires admin user)"
echo ""
echo "Step 3 — STS AssumeRole:"
echo "  AdminRole ARN: $ROLE_ARN"
echo "  Flag in: s3://flag-vault/flag.txt (requires AdminRole)"
echo ""
echo "Step 4 — KMS Decryption Oracle:"
echo "  KMS Key ID: $KEY_ID"
echo "  Encrypted flag: s3://secure-data/encrypted_flag.bin"
echo "  Metadata: s3://secure-data/metadata.json"
echo "=============================================="
