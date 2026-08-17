FROM mongo:7.0
ARG CVE_FLAG=flag{db-06-default}
COPY init.js /tmp/init.js
RUN sed -i "s/__CVE_FLAG__/${CVE_FLAG}/g" /tmp/init.js && \
    mkdir -p /docker-entrypoint-initdb.d && cp /tmp/init.js /docker-entrypoint-initdb.d/init.js
