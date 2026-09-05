#!/bin/sh
# Run php-fpm (background) + nginx (foreground) in one container, serving HTTP on the
# common web ports and HTTPS on the common TLS ports.
set -e

RUNTIME="${FUNNYPOT_IDENTITY_RUNTIME_DIR:-/run/funnypot}"
NGINX_CONFD="${FUNNYPOT_NGINX_CONFD:-/etc/nginx/http.d}"

# Install identity FIRST — before php-fpm, every listener and every worker. Resolves (or creates once)
# the persisted install master, derives the closed keyset, selects + verifies the TLS pair, publishes
# the root-only and www-data-readable runtime bundles under $RUNTIME and root-reads them back.
# Deliberately NOT guarded by `|| true`: with `set -e` a failure stops the container right here, when
# nothing has bound a socket yet — a broken identity is a dark box, never a box serving a fallback
# persona or an unkeyed console.
php /app/bin/funnypot identity:prepare

# Real HTTPS for the admin hostname once Let's Encrypt has issued a cert: identity:prepare rendered the
# named vhost (strictly validated domain, no shell interpolation) only when the live pair verified;
# absent a cert (first boot, before scripts/letsencrypt.sh runs) the block is removed and the hostname
# is served by the default vhost. Named vhost wins by SNI; every other host/IP keeps the selected pair.
if [ -f "$RUNTIME/nginx/admin-ssl.conf" ]; then
    cp "$RUNTIME/nginx/admin-ssl.conf" "$NGINX_CONFD/10-admin-ssl.conf"
else
    rm -f "$NGINX_CONFD/10-admin-ssl.conf"
fi

# None of the identity inputs may reach a child: a php-fpm worker or listener that could read the
# master, a persona override or an operator key path from its environment would make every process a
# disclosure surface. A child PHP process cannot scrub its parent's environment, so this unset is
# mandatory here. Children find their scoped bundle through $RUNTIME (a path, kept).
unset FUNNYPOT_INSTALL_SECRET_FILE FUNNYPOT_INSTALL_SECRET FUNNYPOT_PERSONA_SEED FUNNYPOT_PERSONA_SECRET FUNNYPOT_TLS_CERT_FILE FUNNYPOT_TLS_KEY_FILE FUNNYPOT_FS_SECRET

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
    spawn dnp3        0.0.0.0:20000
    spawn ipmi        0.0.0.0:623
    spawn coap        0.0.0.0:5683
    spawn kerberos    0.0.0.0:88
    spawn ntp         0.0.0.0:123
    spawn winrm       0.0.0.0:5985
    # TR-069 / CWMP router-worm trap on both ports (two cheap select loops so 7548 hits log as 7548).
    spawn cwmp        0.0.0.0:7547
    spawn cwmp        0.0.0.0:7548
    spawn rsync       0.0.0.0:873
    spawn clamav      0.0.0.0:3310
    spawn zookeeper   0.0.0.0:2181
    # databases
    spawn mysql       0.0.0.0:3306
    spawn postgresql  0.0.0.0:5432
    spawn mongodb     0.0.0.0:27017
    spawn cassandra   0.0.0.0:9042
    spawn oracle      0.0.0.0:1521
    # industrial control (SCADA)
    spawn modbus      0.0.0.0:502
    spawn ethernet-ip 0.0.0.0:44818
fi

# Periodic retention: prune the hit store by age + on-disk size. No-op unless FUNNYPOT_RETAIN_DAYS
# / FUNNYPOT_RETAIN_GB are set. Interval seconds via FUNNYPOT_RETAIN_INTERVAL (default hourly).
( while true; do php /app/demo/retention.php || true; sleep "${FUNNYPOT_RETAIN_INTERVAL:-3600}"; done ) &

# Analytics rollup: fold new hits into the small rollup table so the analytics view reads O(buckets)
# instead of scanning the whole hits table. Runs regardless of FUNNYPOT_PROTOCOLS (HTTP hits alone
# need rolling up). No-op unless FUNNYPOT_ROLLUP is on (default). Interval via FUNNYPOT_ROLLUP_INTERVAL
# (default 15s) -- much tighter than retention's hourly cadence, so retention rarely prunes a hit the
# worker has not yet folded.
( while true; do php /app/demo/rollup.php || true; sleep "${FUNNYPOT_ROLLUP_INTERVAL:-15}"; done ) &

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
