FROM wordpress:6.7-php8.2-apache

RUN apt-get update && apt-get install -y --no-install-recommends curl unzip && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Jupiter X Core 4.8.7 — CVE-2025-0366: Contributor+ SVG upload → LFI → RCE
RUN curl -sfSL "https://downloads.wordpress.org/plugin/jupiterx-core.4.8.7.zip" \
        -o /tmp/jupiterx.zip && \
    unzip -q /tmp/jupiterx.zip -d /var/www/html/wp-content/plugins/ && \
    rm /tmp/jupiterx.zip && \
    chown -R www-data:www-data /var/www/html/wp-content/plugins/jupiterx-core

ARG CVE_FLAG=flag{web-06-default}
RUN echo "${CVE_FLAG}" > /flag.txt && chmod 644 /flag.txt

# Create a Contributor user for the attacker to use
COPY create-contributor.php /docker-entrypoint-initdb.d/
