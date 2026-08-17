FROM php:8.2-apache

ARG CVE_FLAG=flag{web-17-default}
RUN echo "${CVE_FLAG}" > /flag.txt && chmod 644 /flag.txt && \
    echo "<?php \$flag = file_get_contents('/flag.txt'); ?>" > /var/www/html/flag_config.php

COPY index.php /var/www/html/index.php

RUN a2enmod rewrite

RUN chown -R www-data:www-data /var/www/html && \
    chmod 644 /var/www/html/index.php /var/www/html/flag_config.php
