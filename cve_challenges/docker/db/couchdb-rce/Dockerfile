FROM couchdb:3.3.3

ARG CVE_FLAG=flag{db-08-default}
USER root
RUN echo "${CVE_FLAG}" > /flag.txt && chmod 644 /flag.txt
# Enable Erlang native query server for arbitrary code execution
# Erlang views have full access to the Erlang runtime (no sandbox)
RUN echo "[native_query_servers]" > /opt/couchdb/etc/local.d/erlang.ini && \
    echo "enable_erlang_query_server = true" >> /opt/couchdb/etc/local.d/erlang.ini && \
    chown couchdb:couchdb /opt/couchdb/etc/local.d/erlang.ini
USER couchdb
