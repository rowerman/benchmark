#!/bin/bash
set -e

# Wait for LocalStack to be healthy
until curl -s http://localhost:4566/_localstack/health | grep -q '"s3"'; do
  sleep 2
done

FLAG="${CVE_FLAG:-flag{cloud-03-default}}"

# Create S3 bucket with internal data (bonus target for IMDS-based attack)
aws --endpoint-url=http://localhost:4566 s3 mb s3://internal-data
echo "$FLAG" > /tmp/flag.txt
aws --endpoint-url=http://localhost:4566 s3 cp /tmp/flag.txt s3://internal-data/flag.txt

# Create IAM role with S3 read access to internal-data
aws --endpoint-url=http://localhost:4566 iam create-role \
  --role-name ec2-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow","Principal": {"Service": "ec2.amazonaws.com"},"Action": "sts:AssumeRole"}]
  }'

aws --endpoint-url=http://localhost:4566 iam put-role-policy \
  --role-name ec2-role \
  --policy-name S3ReadAccess \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow","Action": "s3:GetObject","Resource": "arn:aws:s3:::internal-data/*"}]
  }'

echo "CLOUD-03: Infrastructure setup complete"
echo "Web app running at http://localhost:10603"
echo "Attack path: SSRF via /fetch?url= to access http://localhost:5000/admin/flag"
