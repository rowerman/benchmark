#!/bin/sh
# Gitea initialization wrapper
# Sets up database and admin user via CLI, then starts Gitea server.

set -e

ADMIN_USER="${GITEA_ADMIN_USER:-developer}"
ADMIN_PASS="${GITEA_ADMIN_PASS:-password123}"
CONFIG_FILE="/data/gitea/conf/app.ini"

# Step 1: Start the original entrypoint briefly to generate config
echo "Starting Gitea entrypoint to generate config..."
/bin/s6-svscan /etc/s6 &
S6_PID=$!

# Wait for config file to be generated
for i in $(seq 1 15); do
    if [ -f "$CONFIG_FILE" ]; then
        echo "Config file generated"
        break
    fi
    sleep 1
done

# Stop s6/Gitea briefly
kill $S6_PID 2>/dev/null || true
wait $S6_PID 2>/dev/null || true
sleep 2

# Step 2: Update config for headless install
echo "Updating config for installation..."
sed -i 's/INSTALL_LOCK = false/INSTALL_LOCK = true/' "$CONFIG_FILE" 2>/dev/null || true

# Add a secret key if missing
if grep -q 'SECRET_KEY = $' "$CONFIG_FILE" 2>/dev/null; then
    sed -i 's/SECRET_KEY = $/SECRET_KEY = ci-setup-key-2026/' "$CONFIG_FILE" 2>/dev/null || true
fi

if ! grep -q 'SECRET_KEY = ci-setup-key-2026' "$CONFIG_FILE" 2>/dev/null; then
    echo "SECRET_KEY = ci-setup-key-2026" >> "$CONFIG_FILE"
fi

# Step 3: Run database migration
echo "Running database migration..."
cd /app/gitea
su git -c '/usr/local/bin/gitea --config /data/gitea/conf/app.ini migrate' 2>&1 && \
echo "Migration completed" || \
echo "Migration may have failed, continuing..."

# Step 4: Create admin user (idempotent)
echo "Creating admin user..."
su git -c "/usr/local/bin/gitea --config /data/gitea/conf/app.ini admin user create --username ${ADMIN_USER} --password ${ADMIN_PASS} --email dev@example.com --admin" 2>&1 || \
echo "Admin user already exists or creation skipped"

# Step 5: Restart Gitea via s6
echo "Starting Gitea server..."
exec /bin/s6-svscan /etc/s6
