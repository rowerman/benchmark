FROM postgres:16.6
ARG CVE_FLAG=flag{cloud-16-cross-tenant-db}
RUN apt-get update && apt-get install -y --no-install-recommends curl openssl \
    && rm -rf /var/lib/apt/lists/*
COPY init-db.sh /docker-entrypoint-initdb.d/10-init-db.sh
COPY init.sql /tmp/init.sql
RUN sed -i "s|^INSERT INTO flags VALUES.*|INSERT INTO flags VALUES ('${CVE_FLAG}');|" /tmp/init.sql \
    && cp /tmp/init.sql /docker-entrypoint-initdb.d/20-init.sql
