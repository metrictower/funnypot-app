#!/usr/bin/env bash
#
# Issue (and set up auto-renewal for) a Let's Encrypt certificate for the funnypot admin
# hostname. The running honeypot container answers the ACME HTTP-01 challenge from a mounted
# webroot — no downtime, no extra web server. Run this AFTER scripts/deploy.sh has shipped an
# image with LE_DOMAIN set (which mounts the webroot + /etc/letsencrypt and serves the
# /.well-known/acme-challenge/ path).
#
#   scripts/letsencrypt.sh            # STAGING dry-run first (recommended — no rate limits)
#   scripts/letsencrypt.sh --prod     # issue the real, browser-trusted cert
#
# Server + domain come from scripts/deploy.env (gitignored):
#   FUNNYPOT_HOST, FUNNYPOT_USER, FUNNYPOT_KEY, LE_DOMAIN, LE_EMAIL
#
# Prerequisites the script cannot do for you:
#   - DNS: LE_DOMAIN must already resolve to the server's public IP.
#   - Firewall: the security group must allow inbound 80 (challenge) and 443.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/deploy.env" ]; then
    # shellcheck disable=SC1091
    . "$SCRIPT_DIR/deploy.env"
fi

HOST="${FUNNYPOT_HOST:-}"
USER="${FUNNYPOT_USER:-ec2-user}"
KEY="${FUNNYPOT_KEY:-}"
LE_DOMAIN="${LE_DOMAIN:-}"
LE_EMAIL="${LE_EMAIL:-}"

STAGING=1
for arg in "$@"; do
    case "$arg" in
        --prod) STAGING=0 ;;
        --staging) STAGING=1 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

missing=""
[ -z "$HOST" ] && missing="$missing FUNNYPOT_HOST"
[ -z "$KEY" ] && missing="$missing FUNNYPOT_KEY"
[ -z "$LE_DOMAIN" ] && missing="$missing LE_DOMAIN"
[ -z "$LE_EMAIL" ] && missing="$missing LE_EMAIL"
if [ -n "$missing" ]; then
    echo "error: set these in scripts/deploy.env:$missing" >&2
    exit 1
fi

# The domain is interpolated into the remote command below: validate it locally first so an
# injection-shaped value never reaches ssh (the same grammar the app applies before nginx/paths).
# shellcheck disable=SC1091
. "$SCRIPT_DIR/lib/dns-name.sh"
funnypot_require_dns_name_or_empty LE_DOMAIN "$LE_DOMAIN"

SSH_OPTS=(-i "$KEY" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20)

if [ "$STAGING" = "1" ]; then
    echo "==> Let's Encrypt STAGING for $LE_DOMAIN (test cert — re-run with --prod for the real one)"
else
    echo "==> Let's Encrypt PRODUCTION for $LE_DOMAIN"
fi

# The remote work runs as the SSH user (with sudo for root-only bits). Domain/email/mode are
# passed as environment so the quoted heredoc below expands them on the SERVER, not locally.
ssh "${SSH_OPTS[@]}" "$USER@$HOST" \
    "LE_DOMAIN='$LE_DOMAIN' LE_EMAIL='$LE_EMAIL' STAGING='$STAGING' bash -s" <<'REMOTE'
set -euo pipefail
ACME_DIR="$HOME/funnypot-acme"

# 1. certbot present (distro package, else an isolated pip venv).
if ! command -v certbot >/dev/null 2>&1; then
    echo "==> installing certbot"
    if command -v dnf >/dev/null 2>&1 && sudo dnf install -y certbot >/dev/null 2>&1; then
        :
    elif command -v yum >/dev/null 2>&1 && sudo yum install -y certbot >/dev/null 2>&1; then
        :
    else
        echo "  no distro package; installing certbot in a pip venv"
        sudo python3 -m venv /opt/certbot
        sudo /opt/certbot/bin/pip install --quiet --upgrade pip certbot
        sudo ln -sf /opt/certbot/bin/certbot /usr/local/bin/certbot
    fi
fi
CERTBOT="$(command -v certbot)"
echo "  certbot: $CERTBOT"

# 2. The honeypot container must be up and serving the challenge from the mounted webroot.
if ! sudo docker ps --format '{{.Names}}' | grep -qx funnypot; then
    echo "ERROR: the funnypot container is not running — run scripts/deploy.sh first." >&2
    exit 1
fi
mkdir -p "$ACME_DIR/.well-known/acme-challenge"
PROBE="probe-$$-$(od -An -N6 -tx1 /dev/urandom | tr -d ' ')"
printf '%s' "$PROBE" > "$ACME_DIR/.well-known/acme-challenge/$PROBE"
GOT="$(curl -s -H "Host: $LE_DOMAIN" "http://127.0.0.1/.well-known/acme-challenge/$PROBE" || true)"
rm -f "$ACME_DIR/.well-known/acme-challenge/$PROBE"
if [ "$GOT" != "$PROBE" ]; then
    echo "ERROR: the container is not serving the ACME challenge from the webroot." >&2
    echo "  Re-deploy first — scripts/deploy.sh with LE_DOMAIN set adds the challenge" >&2
    echo "  location and the webroot mount the certbot handshake needs." >&2
    exit 1
fi
echo "  challenge path served OK"

# 3. Issue. Staging goes to a throwaway cert-name so it never occupies the path nginx uses.
ISSUE=(certonly --webroot -w "$ACME_DIR" -d "$LE_DOMAIN" --agree-tos -m "$LE_EMAIL" -n)
if [ "$STAGING" = "1" ]; then
    sudo "$CERTBOT" "${ISSUE[@]}" --staging --cert-name "${LE_DOMAIN}-staging"
    echo
    echo "STAGING OK — the challenge and issuance flow both work."
    echo "Issue the real certificate now:  scripts/letsencrypt.sh --prod"
    exit 0
fi

# Production: real cert at live/$LE_DOMAIN, with a renewal hook that reloads nginx in place.
sudo "$CERTBOT" "${ISSUE[@]}" --cert-name "$LE_DOMAIN" \
    --deploy-hook "docker exec funnypot nginx -s reload"
sudo "$CERTBOT" delete --cert-name "${LE_DOMAIN}-staging" -n >/dev/null 2>&1 || true

# 4. First issuance only: restart so the entrypoint enables the admin HTTPS vhost. Later
#    renewals just reload nginx via the deploy-hook — the cert path stays constant.
echo "==> restarting funnypot to enable the $LE_DOMAIN HTTPS vhost"
sudo docker restart funnypot >/dev/null

# 5. Auto-renewal timer (twice daily; certbot only acts when <30 days remain). The reload
#    hook saved above runs on every successful renewal.
sudo tee /etc/systemd/system/funnypot-certbot.service >/dev/null <<UNIT
[Unit]
Description=Renew funnypot Let's Encrypt certificate

[Service]
Type=oneshot
ExecStart=$CERTBOT renew --quiet
UNIT
sudo tee /etc/systemd/system/funnypot-certbot.timer >/dev/null <<UNIT
[Unit]
Description=Twice-daily funnypot certbot renewal

[Timer]
OnCalendar=*-*-* 03,15:00:00
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now funnypot-certbot.timer >/dev/null 2>&1 || true

echo "==> issued:"
sudo openssl x509 -in "/etc/letsencrypt/live/$LE_DOMAIN/fullchain.pem" -noout -subject -issuer -enddate 2>/dev/null || true
echo "  auto-renewal: funnypot-certbot.timer (reloads nginx on renewal)"
REMOTE

echo "==> done."
if [ "$STAGING" = "0" ]; then
    echo "    Test it: open https://$LE_DOMAIN/ in a browser (valid padlock, no warning)."
fi
