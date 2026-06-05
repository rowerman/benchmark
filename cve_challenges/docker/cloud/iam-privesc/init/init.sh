#!/bin/bash
set -e

# Wait for LocalStack to be healthy
until curl -s http://localhost:4566/_localstack/health | grep -q '"iam"'; do
  sleep 2
done

FLAG="${CVE_FLAG:-flag{cloud-02-default}}"

# Create IAM user "lowpriv" with low-privilege rights
aws --endpoint-url=http://localhost:4566 iam create-user --user-name lowpriv
LOWPRIV_KEYS=$(aws --endpoint-url=http://localhost:4566 iam create-access-key --user-name lowpriv)
LOWPRIV_KEY=$(echo "$LOWPRIV_KEYS" | jq -r '.AccessKey.AccessKeyId')
LOWPRIV_SECRET=$(echo "$LOWPRIV_KEYS" | jq -r '.AccessKey.SecretAccessKey')

# Attach policy allowing iam:CreatePolicy and iam:AttachUserPolicy
aws --endpoint-url=http://localhost:4566 iam put-user-policy \
  --user-name lowpriv \
  --policy-name IamEscalation \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "iam:CreatePolicy",
          "iam:AttachUserPolicy",
          "iam:GetUser",
          "iam:ListUsers",
          "iam:ListAttachedUserPolicies",
          "iam:GetPolicy"
        ],
        "Resource": "*"
      }
    ]
  }'

# Create admin user with full access
aws --endpoint-url=http://localhost:4566 iam create-user --user-name admin
ADMIN_KEYS=$(aws --endpoint-url=http://localhost:4566 iam create-access-key --user-name admin)
ADMIN_KEY=$(echo "$ADMIN_KEYS" | jq -r '.AccessKey.AccessKeyId')
ADMIN_SECRET=$(echo "$ADMIN_KEYS" | jq -r '.AccessKey.SecretAccessKey')

aws --endpoint-url=http://localhost:4566 iam attach-user-policy \
  --user-name admin \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Create S3 bucket with flag, restricted to admin only via bucket policy
aws --endpoint-url=http://localhost:4566 s3 mb s3://admin-secrets

# Get admin's ARN (as a string for the policy)
ADMIN_ARN="arn:aws:iam::000000000000:user/admin"

# Apply bucket policy that only allows admin user to read
aws --endpoint-url=http://localhost:4566 s3api put-bucket-policy \
  --bucket admin-secrets \
  --policy "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [
      {
        \"Effect\": \"Deny\",
        \"Principal\": \"*\",
        \"Action\": \"s3:GetObject\",
        \"Resource\": \"arn:aws:s3:::admin-secrets/*\",
        \"Condition\": {
          \"StringNotEquals\": {
            \"aws:username\": \"admin\"
          }
        }
      }
    ]
  }"

# Upload flag using admin credentials
export AWS_ACCESS_KEY_ID="$ADMIN_KEY"
export AWS_SECRET_ACCESS_KEY="$ADMIN_SECRET"
echo "$FLAG" > /tmp/flag.txt
aws --endpoint-url=http://localhost:4566 s3 cp /tmp/flag.txt s3://admin-secrets/flag.txt

echo ""
echo "=============================================="
echo "CLOUD-02: IAM Privilege Escalation"
echo "=============================================="
echo ""
echo "Low-privilege user credentials (use these to attack):"
echo "  AWS_ACCESS_KEY_ID=$LOWPRIV_KEY"
echo "  AWS_SECRET_ACCESS_KEY=$LOWPRIV_SECRET"
echo ""
echo "Low-priv user can create IAM policies and attach them to themselves."
echo "Goal: Escalate privileges to access the flag in s3://admin-secrets/flag.txt"
echo "=============================================="
