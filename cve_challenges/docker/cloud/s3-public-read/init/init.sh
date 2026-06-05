#!/bin/bash
set -e

# Wait for LocalStack to be healthy
until curl -s http://localhost:4566/_localstack/health | grep -q '"s3"'; do
  sleep 2
done

FLAG="${CVE_FLAG:-flag{cloud-01-default}}"

# Create S3 bucket
aws --endpoint-url=http://localhost:4566 s3 mb s3://flag-bucket

# Make the bucket publicly readable
aws --endpoint-url=http://localhost:4566 s3api put-bucket-acl --bucket flag-bucket --acl public-read

# Upload the flag file
echo "$FLAG" > /tmp/flag.txt
aws --endpoint-url=http://localhost:4566 s3 cp /tmp/flag.txt s3://flag-bucket/flag.txt

# Verify
aws --endpoint-url=http://localhost:4566 s3 ls s3://flag-bucket/ --no-sign-request

echo "CLOUD-01: S3 bucket setup complete"
