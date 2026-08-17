FROM wordpress:6.7-php8.2-apache

RUN apt-get update && apt-get install -y --no-install-recommends unzip && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copypress REST API 1.2 — CVE-2025-8625: hardcoded JWT secret + no file-type validation
# Plugin removed from WordPress.org — bundled locally
COPY copypress-rest-api.1.2.zip /tmp/copypress.zip
RUN unzip -q /tmp/copypress.zip -d /var/www/html/wp-content/plugins/ && \
    rm /tmp/copypress.zip && \
    chown -R www-data:www-data /var/www/html/wp-content/plugins/copypress-rest-api

ARG CVE_FLAG=flag{web-05-default}
RUN echo "${CVE_FLAG}" > /flag.txt && chmod 644 /flag.txt
