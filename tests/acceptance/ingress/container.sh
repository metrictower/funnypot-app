#!/bin/sh
set -eu
# Only the production identity preparer, nginx and PHP-FPM run. Do NOT invoke /entrypoint.sh:
# that would start protocol listeners, fetchers and report drain workers outside this acceptance.
export FUNNYPOT_DB=/app/demo/storage/funnypot.sqlite
export FUNNYPOT_LOG=/app/demo/storage/hits.log
export FUNNYPOT_IDENTITY_RUNTIME_DIR=/run/funnypot
export FUNNYPOT_LE_DOMAIN=admin.ingress.invalid
export FUNNYPOT_CAPTURE_RAW=1
export FUNNYPOT_LLM=0 FUNNYPOT_AI_API=0 FUNNYPOT_DOCKER_API=0 FUNNYPOT_TARPIT=0
export FUNNYPOT_SLEEP_DECOY=0 FUNNYPOT_ENGAGEMENT=0 FUNNYPOT_BLOCKLIST=0
export FUNNYPOT_SELF_IPS=127.0.0.1 FUNNYPOT_TRUSTED_PROXIES=127.0.0.1
# Synthetic local queue controls only; network=none and NO drain worker make delivery impossible.
export FUNNYPOT_ABUSEIPDB_REPORT=1 FUNNYPOT_ABUSEIPDB_KEY=ingress-fixture-not-a-credential
export FUNNYPOT_THREATINTEL_REPORT=1 FUNNYPOT_THREATINTEL_KEY=ingress-fixture-not-a-credential
export FUNNYPOT_THREATINTEL_URL=http://127.0.0.1:1
mkdir -p /etc/letsencrypt/live/admin.ingress.invalid
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=admin.ingress.invalid \
    -keyout /etc/letsencrypt/live/admin.ingress.invalid/privkey.pem \
    -out /etc/letsencrypt/live/admin.ingress.invalid/fullchain.pem >/dev/null 2>&1
chmod 0777 /app/demo/storage
php /app/bin/funnypot identity:prepare >/evidence/identity-prepare.log 2>&1
cp /app/demo/nginx.conf /etc/nginx/http.d/default.conf
cp /run/funnypot/nginx/admin-ssl.conf /etc/nginx/http.d/10-admin-ssl.conf
php /acceptance/setup.php
nginx -V >/evidence/nginx-version.txt 2>&1
nginx -t >/evidence/nginx-config-test.log 2>&1
php-fpm -y /tmp/ingress/fpm.conf -F >/tmp/ingress/fpm-master.log 2>&1 &
fpm_pid=$!
nginx -g 'daemon off;' >/tmp/ingress/nginx-master.log 2>&1 &
nginx_pid=$!
finish() {
    kill "$nginx_pid" "$fpm_pid" 2>/dev/null || true
    wait "$nginx_pid" "$fpm_pid" 2>/dev/null || true
}
trap finish EXIT INT TERM
php -d memory_limit=256M -d max_execution_time=180 /acceptance/check.php
