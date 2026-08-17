FROM wordpress:6.7-php8.2-apache

RUN apt-get update && apt-get install -y --no-install-recommends curl unzip && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# WPBookit 1.0.4 — CVE-2025-6058: unauthenticated file upload via image_upload_handle()
RUN curl -sfSL "https://downloads.wordpress.org/plugin/wpbookit.1.0.4.zip" \
        -o /tmp/wpbookit.zip && \
    unzip -q /tmp/wpbookit.zip -d /var/www/html/wp-content/plugins/ && \
    rm /tmp/wpbookit.zip && \
    chown -R www-data:www-data /var/www/html/wp-content/plugins/wpbookit

ARG CVE_FLAG=flag{web-04-default}
RUN echo "${CVE_FLAG}" > /flag.txt && chmod 644 /flag.txt
