# funnypot standalone honeypot: all-in-one nginx + php-fpm, HTTP + HTTPS across the common web
# ports (handles a scanner's concurrent request flood; php -S could not), plus the TCP emulators.
#   docker build -f demo/Dockerfile -t funnypot .
#   docker run --rm -p 80:80 -p 443:443 -p 8080:8080 -p 2222:2222 funnypot
# Runtime floor is PHP 8.2 (native fsync for the crash-safe install-identity store); the image is 8.3.

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
# the pure-PHP SSH server (curve25519 / ed25519 / aes-ctr). APCu (FP-0242a) is the config store's
# cross-worker read-cache (spec §0/§3) — without it the CredentialStore + ConfigStore APCu paths are
# dead and every config read falls back to a SQLite SELECT. pecl needs the phpize build deps, dropped
# again after the extension is built so they don't bloat the runtime image.
RUN apk add --no-cache nginx openssl sqlite-libs libpng libjpeg-turbo freetype \
    && apk add --no-cache --virtual .build-deps $PHPIZE_DEPS sqlite-dev libpng-dev libjpeg-turbo-dev freetype-dev \
    && docker-php-ext-configure gd --with-jpeg --with-freetype \
    && docker-php-ext-install pdo_sqlite gd pcntl \
    && pecl install apcu \
    && docker-php-ext-enable apcu \
    && apk del .build-deps

# opcache on (artifacts are compiled once, not re-parsed per request) + a worker pool sized for
# concurrency + the shared routing snippet.
COPY demo/opcache.ini            /usr/local/etc/php/conf.d/zz-funnypot.ini
COPY demo/apcu.ini               /usr/local/etc/php/conf.d/zz-funnypot-apcu.ini
COPY demo/fpm-pool.conf          /usr/local/etc/php-fpm.d/zz-funnypot.conf
COPY demo/nginx.conf             /etc/nginx/http.d/default.conf
COPY demo/funnypot-location.conf /etc/nginx/funnypot-location.conf
COPY demo/entrypoint.sh          /entrypoint.sh

WORKDIR /app
# The engine (+ deps) from the composer stage, then the app's own code, compiled artifacts and the
# CLI: the entrypoint (and the deploy preflight, which runs this same image with --network none) runs
# `php /app/bin/funnypot identity:prepare` before anything binds, so bin/ must be in the image.
COPY --from=deps /app/vendor ./vendor
COPY src ./src
COPY resources ./resources
COPY demo ./demo
COPY bin ./bin

# The storage mount stays 0777 (legacy data volume); the install identity lives beneath it in a private
# 0700 root-owned directory that identity:prepare creates and validates on every boot.
RUN chmod +x /entrypoint.sh /app/bin/funnypot \
    && mkdir -p /app/demo/storage \
    && chmod 0777 /app/demo/storage

ENV FUNNYPOT_STYLE=realistic \
    FUNNYPOT_LOG=/app/demo/storage/hits.log

# Every container bind, once — a VIEW of demo/ports.json (documentation only: docker publishes via
# -p in scripts/deploy.sh / compose `ports`). Host-side alias forwards (22->2222, 5800/5901/5902->5900,
# 5061/5080->5060) are publish mappings, not container ports, so they are not listed here.
# `php scripts/check-ports.php` fails on a missing, extra or duplicated port.
# nginx: common HTTP + alt-HTTP + app/panel ports.
EXPOSE 80 81 591 2082 2086 2095 2375 3000 3128 4243 5000 5601 5984 7001 7070 7080 7474 8000 8001 8008 8009 8065 8069 8080 8081 8082 8083 8086 8088 8090 8161 8180 8181 8200 8500 8880 8888 8983 9000 9080 9090 9100 9200 10000 15672
# nginx: HTTPS on the common TLS ports.
EXPOSE 443 2083 2087 2096 4433 4443 8443 8834 8843 9443 10443
# TCP protocol honeypots: mail/cache/shell (redis/ftp/smtp/telnet/memcached/ssh/pop3/imap/finger),
# remote/sync (vnc/rsync/clamav/zookeeper), databases (mysql/postgres/mongodb/mssql/oracle/cassandra),
# SCADA (modbus/enip/s7comm/dnp3), 88 = Kerberos, 5555 = ADB, 5060 = SIP signaling, 3389 = RDP,
# 445 = SMB, 1883 = MQTT, 389 = LDAP, 554 = RTSP, 5985 = WinRM, 7547/7548 = TR-069/CWMP.
EXPOSE 21 23 25 79 88 102 110 143 389 445 502 554 873 1433 1521 1883 2181 2222 3306 3310 3389 5060 5432 5555 5900 5985 6379 7547 7548 9042 11211 20000 27017 44818
# UDP: 123 NTP, 161 SNMP, 623 IPMI, 3478 STUN, 5060 SIP, 5683 CoAP, 10000 SIP RTP media, 47808 BACnet.
EXPOSE 123/udp 161/udp 623/udp 3478/udp 5060/udp 5683/udp 10000/udp 47808/udp

CMD ["/entrypoint.sh"]
