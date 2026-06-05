#!/bin/bash
set -e

# Wait for KMS to be available
until curl -s http://localhost:4566/_localstack/health | grep -q '"kms":"available"'; do
  sleep 2
done

FLAG="${CVE_FLAG:-flag{cloud-08-default}}"

# ──────────────────────────────────────────────
# 1. Create a KMS key for encryption
# ──────────────────────────────────────────────
KEY_ID=$(aws --endpoint-url=http://localhost:4566 kms create-key \
  --description "Flag encryption key" \
  --key-usage ENCRYPT_DECRYPT \
  --query 'KeyMetadata.KeyId' \
  --output text)
echo "Created KMS key: $KEY_ID"

# ──────────────────────────────────────────────
# 2. Create IAM user with only kms:Decrypt permission
#    (no kms:Encrypt, no kms:Admin — pure decryption oracle)
# ──────────────────────────────────────────────
aws --endpoint-url=http://localhost:4566 iam create-user --user-name user

aws --endpoint-url=http://localhost:4566 iam put-user-policy \
  --user-name user \
  --policy-name UserPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "kms:Decrypt",
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "s3:GetObject",
          "s3:ListBucket"
        ],
        "Resource": "*"
      }
    ]
  }'

# Generate access keys
USER_KEYS=$(aws --endpoint-url=http://localhost:4566 iam create-access-key --user-name user)
USER_KEY=$(echo "$USER_KEYS" | jq -r '.AccessKey.AccessKeyId')
USER_SECRET=$(echo "$USER_KEYS" | jq -r '.AccessKey.SecretAccessKey')

# ──────────────────────────────────────────────
# 3. Encrypt the flag using the KMS key
# ──────────────────────────────────────────────
echo -n "$FLAG" > /tmp/flag-plain.txt

CIPHERTEXT_B64=$(aws --endpoint-url=http://localhost:4566 kms encrypt \
  --key-id "$KEY_ID" \
  --plaintext fileb:///tmp/flag-plain.txt \
  --query CiphertextBlob \
  --output text)

# Decode base64 ciphertext to raw binary for storage
echo "$CIPHERTEXT_B64" | base64 -d > /tmp/encrypted_flag.bin

# ──────────────────────────────────────────────
# 4. Store encrypted flag in S3 bucket
# ──────────────────────────────────────────────
aws --endpoint-url=http://localhost:4566 s3 mb s3://secure-data
aws --endpoint-url=http://localhost:4566 s3 cp /tmp/encrypted_flag.bin s3://secure-data/encrypted_flag.bin

# Also store key ID metadata
echo "{\"key_id\": \"$KEY_ID\", \"algorithm\": \"SYMMETRIC_DEFAULT\"}" > /tmp/metadata.json
aws --endpoint-url=http://localhost:4566 s3 cp /tmp/metadata.json s3://secure-data/metadata.json

# Clean up temp files
rm -f /tmp/flag-plain.txt /tmp/encrypted_flag.bin /tmp/metadata.json

echo ""
echo "=============================================="
echo "CLOUD-08: KMS Decryption Oracle"
echo "=============================================="
echo ""
echo "LocalStack available at http://localhost:10608"
echo ""
echo "User credentials (use these to attack):"
echo "  AWS_ACCESS_KEY_ID=$USER_KEY"
echo "  AWS_SECRET_ACCESS_KEY=$USER_SECRET"
echo ""
echo "Target KMS Key ID: $KEY_ID"
echo "Encrypted flag stored in: s3://secure-data/encrypted_flag.bin"
echo "Key metadata: s3://secure-data/metadata.json"
echo ""
echo "Vulnerability: IAM user has kms:Decrypt permission (decryption oracle)"
echo "  but no kms:Encrypt, kms:CreateKey, or admin access"
echo ""
echo "Exploit:"
echo "  1. Download the encrypted flag from S3:"
echo "     aws --endpoint-url=http://localhost:10608 s3 cp \\"
echo "       s3://secure-data/encrypted_flag.bin /tmp/enc.bin"
echo ""
echo "  2. Decrypt using KMS (user has kms:Decrypt):"
echo "     aws --endpoint-url=http://localhost:10608 kms decrypt \\"
echo "       --ciphertext-blob fileb:///tmp/enc.bin \\"
echo "       --output text --query Plaintext | base64 -d"
echo ""
echo "Goal: Decrypt the flag using the KMS decryption oracle"
echo "=============================================="
