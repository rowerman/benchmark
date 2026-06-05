#!/bin/bash
set -e

# Wait for SQS to be available
until curl -s http://localhost:4566/_localstack/health | grep -q '"sqs":"available"'; do
  sleep 2
done

FLAG="${CVE_FLAG:-flag{cloud-06-default}}"

# Create the orders queue (no IAM policy restricting access - world-readable)
QUEUE_URL=$(aws --endpoint-url=http://localhost:4566 sqs create-queue \
  --queue-name orders-queue \
  --query 'QueueUrl' \
  --output text)
echo "Created orders queue: $QUEUE_URL"

# Also create a hidden queue with a less obvious name
aws --endpoint-url=http://localhost:4566 sqs create-queue --queue-name flag-queue
FLAG_QUEUE_URL=$(aws --endpoint-url=http://localhost:4566 sqs get-queue-url \
  --queue-name flag-queue \
  --query 'QueueUrl' \
  --output text)

# Send messages to orders-queue (intercepted by attacker via list-queues + receive-message)
aws --endpoint-url=http://localhost:4566 sqs send-message \
  --queue-url "$QUEUE_URL" \
  --message-body "Order #1234: Customer test-user, Item: Wireless Keyboard"

aws --endpoint-url=http://localhost:4566 sqs send-message \
  --queue-url "$QUEUE_URL" \
  --message-body "Order #5678: Customer demo-user, Item: USB Hub"

# The flag is in a message on the orders-queue
aws --endpoint-url=http://localhost:4566 sqs send-message \
  --queue-url "$QUEUE_URL" \
  --message-body "Flag: $FLAG"

# Also store flag in the hidden queue (bonus)
aws --endpoint-url=http://localhost:4566 sqs send-message \
  --queue-url "$FLAG_QUEUE_URL" \
  --message-body "Backup flag: $FLAG"

echo ""
echo "=============================================="
echo "CLOUD-06: SQS Message Interception"
echo "=============================================="
echo ""
echo "LocalStack available at http://localhost:10606"
echo ""
echo "Vulnerability: SQS queues have no access policy - world-readable"
echo ""
echo "Exploit:"
echo "  1. List queues to discover queue URLs:"
echo "     aws --endpoint-url=http://localhost:10606 sqs list-queues"
echo ""
echo "  2. Receive messages from the discovered queue:"
echo '     QUEUE_URL="http://localhost:10606/000000000000/orders-queue"'
echo "     aws --endpoint-url=http://localhost:10606 sqs receive-message \\"
echo "       --queue-url \"\$QUEUE_URL\" --max-number-of-messages 10"
echo ""
echo "Goal: Retrieve the flag message from the orders-queue"
echo "=============================================="
