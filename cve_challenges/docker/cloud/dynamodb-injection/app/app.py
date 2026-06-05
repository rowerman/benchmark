import os
import time
import json
from flask import Flask, request, jsonify
import boto3

app = Flask(__name__)

# Connect to LocalStack DynamoDB
dynamodb = boto3.resource(
    'dynamodb',
    endpoint_url=os.environ.get('AWS_ENDPOINT', 'http://localhost:4566'),
    region_name=os.environ.get('AWS_REGION', 'us-east-1'),
    aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID', 'fake'),
    aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY', 'fake')
)

# Wait for the DynamoDB table to exist (created by init.sh)
table_name = 'users'
for attempt in range(30):
    try:
        tables = dynamodb.meta.client.list_tables()['TableNames']
        if table_name in tables:
            break
    except Exception:
        pass
    time.sleep(2)
else:
    print("Warning: DynamoDB table 'users' not found after 60 seconds")

table = dynamodb.Table(table_name)


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    username = data.get('username', '')
    password = data.get('password', '')

    # VULNERABLE: String concatenation in FilterExpression allows NoSQL injection
    # Attacker can inject: admin' OR '1'='1
    try:
        response = table.scan(
            FilterExpression=f"username = '{username}' AND password = '{password}'"
        )
        items = response.get('Items', [])
        if items:
            user = items[0]
            # Return flag if present (admin user has it)
            flag = user.get('flag', None)
            result = {
                "message": "Login successful",
                "user": user.get('username'),
            }
            if flag:
                result["flag"] = flag
            return jsonify(result)
        else:
            return jsonify({"message": "Login failed"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/')
def index():
    return jsonify({
        "message": "DynamoDB Login API",
        "endpoints": {
            "POST /login": "Authenticate with username and password (JSON body)"
        }
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
