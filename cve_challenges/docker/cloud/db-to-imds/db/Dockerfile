FROM postgres:16.6
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
COPY init.sql /docker-entrypoint-initdb.d/
