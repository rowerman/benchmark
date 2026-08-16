#!/bin/bash
set -e
echo "[victim-pg] fetching provider internal CA from internal-ca..."
for i in $(seq 1 30); do
  if curl -sf "http://internal-ca:5000/ca" -o /tmp/ca.json; then break; fi
  sleep 1
done
CA_B64=$(grep -o '"ca":"[^"]*"' /tmp/ca.json | sed 's/"ca":"//; s/"$//')
echo "$CA_B64" | base64 -d > "$PGDATA/root.crt"
chmod 600 "$PGDATA/root.crt"
chown postgres:postgres "$PGDATA/root.crt"

echo "[victim-pg] generating server certificate..."
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -subj "/CN=victim-pg" -keyout "$PGDATA/server.key" -out "$PGDATA/server.crt" 2>/dev/null
chmod 600 "$PGDATA/server.key"
chown postgres:postgres "$PGDATA/server.key" "$PGDATA/server.crt"

echo "[victim-pg] enabling ssl and internal-subnet cert auth..."
cat >> "$PGDATA/postgresql.conf" <<'EOF'
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
ssl_ca_file = 'root.crt'
EOF
cat >> "$PGDATA/pg_hba.conf" <<'EOF'
# internal subnet: replication user authenticates with a client certificate
# from the provider-internal CA. The server only verifies the CA signature
# (verify-ca) and never re-checks the certificate CN -- the ExtraReplica
# mis-anchored CN regex, in effect.
hostssl replication replication 10.0.0.0/24 trust clientcert=verify-ca
EOF
echo "[victim-pg] init done"
