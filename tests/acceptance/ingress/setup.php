<?php

declare(strict_types=1);

// Test-only overlays do not edit the production config/include or front controller.
mkdir('/tmp/ingress', 0777);
chmod('/tmp/ingress', 0777);
foreach (['fpm-calls.log', 'php-error.log'] as $name) {
    file_put_contents('/tmp/ingress/' . $name, '');
    chmod('/tmp/ingress/' . $name, 0666);
}
file_put_contents('/tmp/ingress/fpm.conf', <<<'CONF'
[global]
daemonize = no
error_log = /tmp/ingress/fpm-error.log
include = /usr/local/etc/php-fpm.d/www.conf
include = /usr/local/etc/php-fpm.d/zz-funnypot.conf
[www]
clear_env = no
access.log = /tmp/ingress/fpm-access.log
access.format = "ingress-fpm-request"
php_admin_value[auto_prepend_file] = /acceptance/prepend.php
php_admin_value[error_log] = /tmp/ingress/php-error.log

CONF);
// A real, isolated special-response body-timeout path tests static 408 bytes. It is not evidence
// for partial-header timeout behavior, and no new location or body timeout enters the production app.
file_put_contents('/etc/nginx/http.d/90-ingress-probe.conf', <<<'CONF'
server {
    listen 127.0.0.1:8099;
    server_name ingress-probe.invalid;
    server_tokens off;
    access_log off;
    set $funnypot_https off;
    include /etc/nginx/funnypot-location.conf;
    location = /__ingress_body_timeout {
        client_body_timeout 1s;
        include fastcgi_params;
        fastcgi_pass 127.0.0.1:9001;
        fastcgi_param SCRIPT_FILENAME /app/demo/index.php;
    }
}

CONF);
mkdir('/var/acme/.well-known/acme-challenge', 0755, true);
file_put_contents('/var/acme/.well-known/acme-challenge/ingress-token', 'ingress-acme-control');
