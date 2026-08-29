# funnypot standalone honeypot: all-in-one nginx + php-fpm, HTTP + HTTPS across the common web
# ports (handles a scanner's concurrent request flood; php -S could not), plus the TCP emulators.
#   docker build -f demo/Dockerfile -t funnypot .
#   docker run --rm -p 80:80 -p 443:443 -p 8080:8080 -p 2222:2222 funnypot

# --- deps: resolve the HTTP engine (metrictower/funnypot-core) + its deps into vendor/ ---
# funnypot-core is pulled from its GitHub repo (a vcs repository in composer.json) until it is on
# Packagist. Platform reqs (ext-sodium/openssl) are checked in the runtime image, not here.
FROM composer:2 AS deps
WORKDIR /app
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-scripts --no-interaction --prefer-dist --no-progress --ignore-platform-reqs

# --- runtime ---
FROM php:8.3-fpm-alpine

# nginx + openssl; pdo_sqlite for the dashboard store; sodium/openssl are built into the base for
# the pure-PHP SSH server (curve25519 / ed25519 / aes-ctr).
RUN apk add --no-cache nginx openssl sqlite-libs libpng libjpeg-turbo freetype \
    && apk add --no-cache --virtual .build-deps sqlite-dev libpng-dev libjpeg-turbo-dev freetype-dev \
    && docker-php-ext-configure gd --with-jpeg --with-freetype \
    && docker-php-ext-install pdo_sqlite gd \
    && apk del .build-deps

# opcache on (artifacts are compiled once, not re-parsed per request) + a worker pool sized for
# concurrency + the shared routing snippet.
COPY demo/opcache.ini            /usr/local/etc/php/conf.d/zz-funnypot.ini
COPY demo/fpm-pool.conf          /usr/local/etc/php-fpm.d/zz-funnypot.conf
COPY demo/nginx.conf             /etc/nginx/http.d/default.conf
COPY demo/funnypot-location.conf /etc/nginx/funnypot-location.conf
COPY demo/entrypoint.sh          /entrypoint.sh

WORKDIR /app
# The engine (+ deps) from the composer stage, then the app's own code and compiled artifacts.
COPY --from=deps /app/vendor ./vendor
COPY src ./src
COPY resources ./resources
COPY demo ./demo

RUN chmod +x /entrypoint.sh \
    && mkdir -p /app/demo/storage \
    && chmod 0777 /app/demo/storage

ENV FUNNYPOT_STYLE=realistic \
    FUNNYPOT_LOG=/app/demo/storage/hits.log

# Common HTTP + alt-HTTP + app/panel ports, and HTTPS on the common TLS ports.
# (Documentation only; docker publishes ports via -p in scripts/deploy.sh. Keep in sync.)
EXPOSE 80 81 88 591 2082 2086 2095 2375 3000 3128 4243 5000 5555 5601 5984 7001 7070 7080 7474 8000 8001 8008 8009 8065 8069 8080 8081 8082 8083 8086 8088 8090 8161 8180 8181 8200 8500 8880 8888 8983 9000 9080 9090 9100 9200 10000 15672
EXPOSE 443 2083 2087 2096 4433 4443 8443 8834 8843 9443 10443
# TCP protocol honeypots: mail/cache/shell (redis/ftp/smtp/telnet/memcached/ssh/pop3/imap/finger),
# remote/sync (vnc/rsync/clamav/zookeeper), databases (mysql/postgres/mongodb), SCADA (modbus/enip).
# 5800/5901/5902 are extra VNC scan ports the deploy forwards to the single 5900 listener.
# 5060 = SIP signaling (TCP+UDP); 10000/udp = SIP RTP media (caller audio + DTMF); 3389 = RDP; 445 = SMB.
EXPOSE 21 23 25 79 110 143 445 502 873 2181 2222 3306 3310 3389 5060 5060/udp 5432 5800 5900 5901 5902 6379 10000/udp 11211 27017 44818

CMD ["/entrypoint.sh"]
