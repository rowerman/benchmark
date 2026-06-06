#!/bin/bash
set -e

# Wait for LocalStack to be healthy
until curl -s http://localhost:4566/_localstack/health | grep -q '"iam"'; do
  sleep 2
done

echo "=== Chain-39 Combined Init: SQS → IAM → Lambda → KMS ==="

# ──────────────────────────────────────────────
# Step 1: SQS Queue with Credentials (CLOUD-06)
# ──────────────────────────────────────────────
QUEUE_URL=$(aws --endpoint-url=http://localhost:4566 sqs create-queue \
  --queue-name orders-queue \
  --query 'QueueUrl' --output text)

# Place flag message in orders-queue
aws --endpoint-url=http://localhost:4566 sqs send-message \
  --queue-url "$QUEUE_URL" \
  --message-body "Flag: flag{c39-step1-sqs}"

# Send some decoy messages
aws --endpoint-url=http://localhost:4566 sqs send-message \
  --queue-url "$QUEUE_URL" \
  --message-body "Order #1234: Customer test-user, Item: Wireless Keyboard"

aws --endpoint-url=http://localhost:4566 sqs send-message \
  --queue-url "$QUEUE_URL" \
  --message-body "Order #5678: Customer demo-user, Item: USB Hub"

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
      "Action":["iam:CreatePolicy","iam:AttachUserPolicy","iam:GetUser","iam:ListUsers","iam:ListAttachedUserPolicies","iam:GetPolicy","lambda:ListFunctions","lambda:GetFunction","lambda:InvokeFunction","sqs:ListQueues","sqs:ReceiveMessage","sqs:GetQueueUrl"],
      "Resource":"*"
    }]
  }'

# Embed lowpriv credentials in an SQS message
aws --endpoint-url=http://localhost:4566 sqs send-message \
  --queue-url "$QUEUE_URL" \
  --message-body "{\"note\":\"Deployment credentials\",\"AWS_ACCESS_KEY_ID\":\"$LOWPRIV_KEY\",\"AWS_SECRET_ACCESS_KEY\":\"$LOWPRIV_SECRET\"}"

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
echo "flag{c39-step2-iam}" > /tmp/step2.txt
aws --endpoint-url=http://localhost:4566 s3 cp /tmp/step2.txt s3://admin-secrets/flag.txt
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

# ──────────────────────────────────────────────
# Step 3: Lambda Command Injection (CLOUD-04)
# ──────────────────────────────────────────────
aws --endpoint-url=http://localhost:4566 iam create-role \
  --role-name lambda-exec \
  --assume-role-policy-document '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"
    }]
  }' 2>/dev/null || true

cat > /tmp/lambda_function.py << 'PYEOF'
def handler(event, context):
    import subprocess
    cmd = event.get('cmd', 'echo "no command"')
    result = subprocess.check_output(cmd, shell=True).decode()
    return {'result': result}
PYEOF

cd /tmp
zip lambda_function.zip lambda_function.py

aws --endpoint-url=http://localhost:4566 lambda create-function \
  --function-name process-order \
  --runtime python3.11 \
  --role arn:aws:iam::000000000000:role/lambda-exec \
  --handler lambda_function.handler \
  --zip-file fileb:///tmp/lambda_function.zip \
  --environment "Variables={FLAG=flag{c39-step3-lambda}}"

# ──────────────────────────────────────────────
# Step 4: KMS Decryption Oracle (CLOUD-08)
# ──────────────────────────────────────────────
KEY_ID=$(aws --endpoint-url=http://localhost:4566 kms create-key \
  --description "Flag encryption key" \
  --key-usage ENCRYPT_DECRYPT \
  --query 'KeyMetadata.KeyId' --output text)

aws --endpoint-url=http://localhost:4566 s3 mb s3://secure-data

echo -n "flag{c39-step4-kms}" > /tmp/final.txt
CIPHERTEXT_B64=$(aws --endpoint-url=http://localhost:4566 kms encrypt \
  --key-id "$KEY_ID" \
  --plaintext fileb:///tmp/final.txt \
  --query CiphertextBlob --output text)
echo "$CIPHERTEXT_B64" | base64 -d > /tmp/encrypted.bin
aws --endpoint-url=http://localhost:4566 s3 cp /tmp/encrypted.bin s3://secure-data/encrypted_flag.bin
echo "{\"key_id\":\"$KEY_ID\",\"algorithm\":\"SYMMETRIC_DEFAULT\"}" > /tmp/meta.json
aws --endpoint-url=http://localhost:4566 s3 cp /tmp/meta.json s3://secure-data/metadata.json

# Cleanup
rm -f /tmp/step2.txt /tmp/final.txt /tmp/encrypted.bin /tmp/meta.json /tmp/lambda_function.py /tmp/lambda_function.zip

echo ""
echo "=============================================="
echo "Chain-39: SQS → IAM → Lambda → KMS"
echo "=============================================="
echo ""
echo "Step 1 — SQS Message Interception (no auth needed):"
echo "  aws sqs list-queues --endpoint-url http://localhost:11639"
echo "  aws sqs receive-message --endpoint-url http://localhost:11639 --queue-url \"\$QUEUE_URL\" --max-number-of-messages 10"
echo ""
echo "Step 2 — IAM Privilege Escalation:"
echo "  Low-priv credentials are embedded in one of the SQS messages"
echo "  Username: lowpriv"
echo "  Flag in: s3://admin-secrets/flag.txt (requires admin user)"
echo ""
echo "Step 3 — Lambda Command Injection:"
echo '  aws lambda invoke --endpoint-url http://localhost:11639 --function-name process-order --payload '"'"'{"cmd":"echo $FLAG"}'"'"' /tmp/out'
echo ""
echo "Step 4 — KMS Decryption Oracle:"
echo "  KMS Key ID: $KEY_ID"
echo "  Encrypted flag: s3://secure-data/encrypted_flag.bin"
echo "  Metadata: s3://secure-data/metadata.json"
echo "=============================================="
