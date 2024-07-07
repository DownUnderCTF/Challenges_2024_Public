FROM php:8.3-apache

RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"
RUN sed -i 's/Listen 80/Listen 1337/g' /etc/apache2/ports.conf

COPY . /var/www/html/
