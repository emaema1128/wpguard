# 検証用: Debian 13 の Apache + PHP 8.3 に ModSecurity と OWASP CRS を入れたもの
#   docker build -t wpguard-modsec -f docs/modsecurity/Dockerfile docs/modsecurity
FROM php:8.3-apache
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libapache2-mod-security2 modsecurity-crs >/dev/null \
 && docker-php-ext-install mysqli >/dev/null 2>&1 \
 && rm -rf /var/lib/apt/lists/*
COPY wpguard.conf /etc/modsecurity/wpguard.conf
RUN sed 's/^SecRuleEngine .*/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf-recommended > /etc/modsecurity/modsecurity.conf
