FROM postgres:16.6
RUN apt-get update && apt-get install -y --no-install-recommends curl openssl \
    && rm -rf /var/lib/apt/lists/*
COPY init-db.sh /docker-entrypoint-initdb.d/10-init-db.sh
COPY init.sql /docker-entrypoint-initdb.d/20-init.sql
