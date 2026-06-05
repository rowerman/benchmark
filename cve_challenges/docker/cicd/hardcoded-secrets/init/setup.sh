#!/bin/sh
# CI-03: Initialize Gitea with hardcoded secrets scenario
set -e

GITEA_URL="${GITEA_URL:-http://gitea:3000}"
ADMIN_USER="${ADMIN_USER:-developer}"
ADMIN_PASS="${ADMIN_PASS:-password123}"
CVE_FLAG="${CVE_FLAG:-flag{ci-03-default}}"

# Install curl if not present
apk add --no-cache curl jq >/dev/null 2>&1 || true

echo "Waiting for Gitea..."
for i in $(seq 1 30); do
    if curl -sf "$GITEA_URL/api/v1/version" >/dev/null 2>&1; then
        break
    fi
    sleep 2
done
echo "Gitea is ready"

# Install Gitea (create admin user via web install form)
echo "Installing Gitea..."
curl -sf -X POST "$GITEA_URL/install" \
    -d "db_type=SQLite3" \
    -d "db_host=localhost:3306" \
    -d "db_user=root" \
    -d "db_passwd=" \
    -d "db_name=gitea" \
    -d "ssl_mode=disable" \
    -d "app_name=Gitea" \
    -d "repo_root_path=/data/git/repositories" \
    -d "lfs_root_path=/data/lfs" \
    -d "run_user=git" \
    -d "domain=localhost" \
    -d "http_port=3000" \
    -d "app_url=$GITEA_URL/" \
    -d "username=$ADMIN_USER" \
    -d "password=$ADMIN_PASS" \
    -d "reenter_password=$ADMIN_PASS" \
    -d "email=dev@example.com" \
    -d "enable_captcha=false" \
    -d "offline_mode=on" \
    -d "disable_gravatar=on" \
    -d "enable_open_id_sign_in=off" \
    -d "enable_open_id_sign_up_auto=off"
sleep 5

# Get API token
echo "Getting API token..."
TOKEN_RESP=$(curl -sf -X POST "$GITEA_URL/api/v1/users/$ADMIN_USER/tokens" \
    -H "Content-Type: application/json" \
    -d '{"name":"setup"}' \
    -u "$ADMIN_USER:$ADMIN_PASS")
TOKEN=$(echo "$TOKEN_RESP" | jq -r '.sha1' 2>/dev/null || echo "")

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    # Try listing existing tokens
    TOKEN=$(curl -sf "$GITEA_URL/api/v1/users/$ADMIN_USER/tokens" \
        -u "$ADMIN_USER:$ADMIN_PASS" | jq -r '.[0].sha1' 2>/dev/null || echo "")
fi

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    echo "ERROR: Could not get API token"
    exit 1
fi
echo "Token obtained"

AUTH="Authorization: token $TOKEN"

# Create public repo: frontend-app
echo "Creating frontend-app (public)..."
curl -sf -X POST "$GITEA_URL/api/v1/user/repos" \
    -H "$AUTH" \
    -H "Content-Type: application/json" \
    -d '{"name":"frontend-app","auto_init":true,"private":false}'
sleep 2

# Create hardcoded API token that has access to both repos
# We'll use the developer's own token as the "hardcoded" credential
API_TOKEN="$TOKEN"

# Create .ci/config.yml with hardcoded token
CONFIG_YML="api_version: v1
secrets:
  gitea_token: \"$API_TOKEN\"
deploy:
  target: internal-api
  endpoint: $GITEA_URL/api/v1

# WARNING: DO NOT COMMIT THIS FILE WITH REAL TOKENS
# This is a template - replace with your actual token
"
CONFIG_B64=$(echo "$CONFIG_YML" | base64 -w0)

echo "Creating .ci/config.yml in frontend-app..."
curl -sf -X PUT "$GITEA_URL/api/v1/repos/$ADMIN_USER/frontend-app/contents/.ci/config.yml" \
    -H "$AUTH" \
    -H "Content-Type: application/json" \
    -d "{\"content\":\"$CONFIG_B64\",\"message\":\"Add CI config with deployment token\"}"
sleep 2

# Create private repo: internal-api
echo "Creating internal-api (private)..."
curl -sf -X POST "$GITEA_URL/api/v1/user/repos" \
    -H "$AUTH" \
    -H "Content-Type: application/json" \
    -d '{"name":"internal-api","auto_init":true,"private":true}'
sleep 2

# Create flag.txt in internal-api
FLAG_B64=$(echo "$CVE_FLAG" | base64 -w0)
echo "Creating flag.txt in internal-api..."
curl -sf -X PUT "$GITEA_URL/api/v1/repos/$ADMIN_USER/internal-api/contents/flag.txt" \
    -H "$AUTH" \
    -H "Content-Type: application/json" \
    -d "{\"content\":\"$FLAG_B64\",\"message\":\"Add flag\"}"

echo ""
echo "CI-03 initialization complete"
echo "Public repo: $ADMIN_USER/frontend-app"
echo "Private repo: $ADMIN_USER/internal-api"
