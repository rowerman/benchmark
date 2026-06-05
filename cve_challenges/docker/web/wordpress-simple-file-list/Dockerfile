FROM wordpress:6.7-php8.2-apache

# Install tools and vulnerable Simple File List plugin 4.2.2
RUN set -ex; \
    apt-get update -qq && apt-get install -y --no-install-recommends curl unzip && \
    apt-get clean && rm -rf /var/lib/apt/lists/*; \
    curl -sfSL "https://downloads.wordpress.org/plugin/simple-file-list.4.2.2.zip" \
        -o /tmp/simple-file-list.zip; \
    unzip -q /tmp/simple-file-list.zip -d /var/www/html/wp-content/plugins/; \
    rm /tmp/simple-file-list.zip; \
    chown -R www-data:www-data /var/www/html/wp-content/plugins/simple-file-list

# Flag file outside web root (requires RCE to read)
ARG CVE_FLAG=flag{web-03-default}
RUN echo "${CVE_FLAG}" > /flag.txt && chmod 644 /flag.txt
