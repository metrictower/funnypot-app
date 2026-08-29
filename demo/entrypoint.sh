#!/bin/sh
# Run php-fpm (background) + nginx (foreground) in one container, serving HTTP on the
# common web ports and HTTPS (self-signed) on the common TLS ports.
set -e

CRT=/etc/nginx/funnypot.crt
KEY=/etc/nginx/funnypot.key
CN_FILE=/etc/nginx/funnypot.cn

# Generate a self-signed cert on first boot (persisted if /etc/nginx is a volume).
# The CN/SAN are per-host so the cert is not byte-identical across deployments (a shared
# CN=localhost/no-SAN cert is a content-hash clustering tell and unusual for a public host).
# Name precedence: operator-set FUNNYPOT_CN, else the container hostname, else a stable random
# subdomain saved next to the cert so it survives restarts. Derived names are persisted so the
# CN stays fixed even if the cert is later regenerated.
if [ ! -f "$CRT" ] || [ ! -f "$KEY" ]; then
    if [ -n "${FUNNYPOT_CN:-}" ]; then
        CN="$FUNNYPOT_CN"
    elif [ -s "$CN_FILE" ]; then
        CN=$(cat "$CN_FILE")
    else
        CN=$(hostname 2>/dev/null || true)
        case "$CN" in
            ''|localhost|localhost.*) CN= ;;
        esac
        if [ -z "$CN" ]; then
            RAND=$(openssl rand -hex 5 2>/dev/null || true)
            [ -n "$RAND" ] || RAND=$(date +%s | tail -c 7)
            CN="srv-${RAND}.internal"
        fi
        printf '%s\n' "$CN" > "$CN_FILE"
    fi

    # subjectAltName mirrors the CN; append the host's public DNS when the deploy supplies it.
    SAN="DNS:${CN}"
    if [ -n "${FUNNYPOT_PUBLIC_DNS:-}" ] && [ "$FUNNYPOT_PUBLIC_DNS" != "$CN" ]; then
        SAN="${SAN},DNS:${FUNNYPOT_PUBLIC_DNS}"
    fi

    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "$KEY" -out "$CRT" \
        -subj "/CN=${CN}" \
        -addext "subjectAltName=${SAN}" >/dev/null 2>&1
fi

# Real HTTPS for the admin hostname once Let's Encrypt has issued a cert (mounted from the
# host at /etc/letsencrypt). Named vhost wins by SNI; every other host/IP keeps self-signed.
# Absent a cert (first boot, before scripts/letsencrypt.sh runs), the block is skipped and
# the hostname is served by the default self-signed 443 vhost.
ADMIN_CONF=/etc/nginx/http.d/10-admin-ssl.conf
LE_LIVE="/etc/letsencrypt/live/${FUNNYPOT_LE_DOMAIN:-__none__}"
if [ -n "${FUNNYPOT_LE_DOMAIN:-}" ] && [ -f "$LE_LIVE/fullchain.pem" ]; then
    cat > "$ADMIN_CONF" <<EOF
server {
    listen 443 ssl;
    server_name ${FUNNYPOT_LE_DOMAIN};
    server_tokens off;
    access_log off;
    ssl_certificate ${LE_LIVE}/fullchain.pem;
    ssl_certificate_key ${LE_LIVE}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    set \$funnypot_https on;
    include /etc/nginx/funnypot-location.conf;
}
EOF
else
    rm -f "$ADMIN_CONF"
fi

php-fpm --daemonize

# Refresh the emulation toggle list from the compiled catalog: new capabilities auto-appear at
# their default, operator choices are preserved. The dashboard + listeners read this file.
php /app/demo/vulns-sync.php || true

# Protocol honeypots: one background listener per protocol (each a bounded select loop). The
# plaintext ones are data-driven emulators; ssh is a full pure-PHP SSH-2.0 server that terminates
# the crypto handshake and drops attackers into the same fake shell as telnet. All log connections
# + every command into the same store the dashboard reads. Disable with FUNNYPOT_PROTOCOLS=0.
if [ "${FUNNYPOT_PROTOCOLS:-1}" != "0" ]; then
    # Respawn a listener if it ever exits. `--restart unless-stopped` only reacts to the CONTAINER
    # dying; a single background listener that hit a fatal would otherwise leave its port silently
    # dead until a manual `docker restart`. The in-process select loops already isolate per-message
    # faults (degrade, never crash); this is the belt-and-braces layer. A 2s backoff keeps a
    # crash-on-boot from hot-looping. Each backgrounded subshell snapshots its own proto/bind.
    spawn() {
        _proto="$1"; _bind="$2"
        ( while true; do
            php /app/demo/listen.php "$_proto" "$_bind"
            echo "funnypot: listener '$_proto' exited (rc=$?), respawning in 2s" >&2
            sleep 2
          done ) &
    }
    spawn redis       0.0.0.0:6379
    spawn ftp         0.0.0.0:21
    spawn smtp        0.0.0.0:25
    spawn telnet      0.0.0.0:23
    spawn memcached   0.0.0.0:11211
    spawn ssh         0.0.0.0:2222
    # mail + misc line services
    spawn pop3        0.0.0.0:110
    spawn imap        0.0.0.0:143
    spawn finger      0.0.0.0:79
    spawn vnc         0.0.0.0:5900
    spawn sip         0.0.0.0:5060
    spawn rdp         0.0.0.0:3389
    spawn smb         0.0.0.0:445
    spawn mssql       0.0.0.0:1433
    spawn mqtt        0.0.0.0:1883
    spawn snmp        0.0.0.0:161
    spawn ldap        0.0.0.0:389
    spawn s7comm      0.0.0.0:102
    spawn adb         0.0.0.0:5555
    spawn bacnet      0.0.0.0:47808
    spawn rtsp        0.0.0.0:554
    spawn stun        0.0.0.0:3478
    spawn rsync       0.0.0.0:873
    spawn clamav      0.0.0.0:3310
    spawn zookeeper   0.0.0.0:2181
    # databases
    spawn mysql       0.0.0.0:3306
    spawn postgresql  0.0.0.0:5432
    spawn mongodb     0.0.0.0:27017
    # industrial control (SCADA)
    spawn modbus      0.0.0.0:502
    spawn ethernet-ip 0.0.0.0:44818
fi

# Periodic retention: prune the hit store by age + on-disk size. No-op unless FUNNYPOT_RETAIN_DAYS
# / FUNNYPOT_RETAIN_GB are set. Interval seconds via FUNNYPOT_RETAIN_INTERVAL (default hourly).
( while true; do php /app/demo/retention.php || true; sleep "${FUNNYPOT_RETAIN_INTERVAL:-3600}"; done ) &

# Threat-intel blocklist refresh: fetch attacker feeds into intel.db so hits from known attackers
# are flagged. No-op unless FUNNYPOT_BLOCKLIST=on. Refresh at boot, then every FUNNYPOT_BLOCKLIST_INTERVAL
# seconds (default 6h).
( php /app/demo/blocklist-refresh.php || true; while true; do sleep "${FUNNYPOT_BLOCKLIST_INTERVAL:-21600}"; php /app/demo/blocklist-refresh.php || true; done ) &

# AbuseIPDB report drain: send the reports queued by the web + protocol honeypots. No-op unless
# FUNNYPOT_ABUSEIPDB_REPORT=on with a key. Interval via FUNNYPOT_ABUSEIPDB_DRAIN_INTERVAL (default 60s).
( while true; do sleep "${FUNNYPOT_ABUSEIPDB_DRAIN_INTERVAL:-60}"; php /app/demo/abuse-drain.php || true; done ) &

# Threat Intel report drain: send the reports queued for our own funnypot-mainnet service. No-op unless
# FUNNYPOT_THREATINTEL_REPORT=on with a key. Interval via FUNNYPOT_THREATINTEL_DRAIN_INTERVAL (default 60s).
( while true; do sleep "${FUNNYPOT_THREATINTEL_DRAIN_INTERVAL:-60}"; php /app/demo/threatintel-drain.php || true; done ) &

exec nginx -g 'daemon off;'
