#!/bin/bash
set -e

# Wait for LocalStack to be healthy
until curl -s http://localhost:4566/_localstack/health | grep -q '"lambda"'; do
  sleep 2
done

FLAG="${CVE_FLAG:-flag{cloud-04-default}}"

# Create IAM role for Lambda execution
aws --endpoint-url=http://localhost:4566 iam create-role \
  --role-name lambda-exec \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow","Principal": {"Service": "lambda.amazonaws.com"},"Action": "sts:AssumeRole"}]
  }' 2>/dev/null || true

# Create the Lambda function with vulnerable code
# The function takes a 'cmd' parameter from the event and executes it via shell
cat > /tmp/lambda_function.py << 'PYEOF'
def handler(event, context):
    import subprocess
    cmd = event.get('cmd', 'echo "no command"')
    result = subprocess.check_output(cmd, shell=True).decode()
    return {'result': result}
PYEOF

# Package the code
cd /tmp
zip lambda_function.zip lambda_function.py

# Create Lambda function with FLAG environment variable
aws --endpoint-url=http://localhost:4566 lambda create-function \
  --function-name process-order \
  --runtime python3.11 \
  --role arn:aws:iam::000000000000:role/lambda-exec \
  --handler lambda_function.handler \
  --zip-file fileb:///tmp/lambda_function.zip \
  --environment "Variables={FLAG=$FLAG}"

# Verify
aws --endpoint-url=http://localhost:4566 lambda get-function --function-name process-order

echo ""
echo "=============================================="
echo "CLOUD-04: Lambda Code Injection"
echo "=============================================="
echo ""
echo "Lambda function 'process-order' created with command injection vulnerability."
echo "Flag stored in Lambda environment variable FLAG."
echo ""
echo "Exploit:"
echo '  aws --endpoint-url=http://localhost:10604 lambda invoke --function-name process-order --payload '"'"'{"cmd":"echo $FLAG"}'"'"' /tmp/out; cat /tmp/out'
echo "=============================================="
