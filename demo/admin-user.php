<?php

declare(strict_types=1);

/**
 * Create or reset the operator credential for the colocated admin section (FP-0242b), from the box's
 * shell — a sibling of demo/config-seed.php. This is the recovery path so a deploy that never set
 * FUNNYPOT_ADMIN_PASSWORD (⇒ the bootstrap seed created no user ⇒ the fail-closed panel is
 * unreachable) is recoverable WITHOUT a redeploy: run this to mint or reset the first operator.
 *
 *   php demo/admin-user.php <username> [password]
 *
 * If <password> is omitted it is read from FUNNYPOT_ADMIN_PASSWORD, else prompted on the TTY (never
 * echoed). Writes admin.sqlite on the persisted data volume, beside the hit store — the same file the
 * running container's AdminAuth reads, so the change is live immediately (no restart).
 */

require __DIR__ . '/../vendor/autoload.php';

use Funnypot\App\Admin\AdminAuth;
use Funnypot\App\Config\ConfigStore;

$username = $argv[1] ?? '';
if ($username === '' || in_array($username, ['-h', '--help'], true)) {
    fwrite(STDERR, "usage: php demo/admin-user.php <username> [password]\n");
    fwrite(STDERR, "  password defaults to \$FUNNYPOT_ADMIN_PASSWORD, else a (hidden) TTY prompt.\n");
    exit($username === '' ? 1 : 0);
}

$password = $argv[2] ?? '';
if ($password === '') {
    $env = getenv('FUNNYPOT_ADMIN_PASSWORD');
    if ($env !== false && $env !== '') {
        $password = $env;
    } else {
        fwrite(STDERR, "password for '{$username}': ");
        // Best-effort no-echo prompt; falls back to a plain read if stty is unavailable.
        $hidden = @shell_exec('stty -echo 2>/dev/null');
        $password = rtrim((string) fgets(STDIN), "\r\n");
        @shell_exec('stty echo 2>/dev/null');
        fwrite(STDERR, "\n");
    }
}

if ($password === '') {
    fwrite(STDERR, "admin-user: a non-empty password is required\n");
    exit(1);
}

// admin.sqlite lives in the same storage dir as config.sqlite / the hit store (see demo/index.php).
$storageDir = dirname(ConfigStore::defaultDbPath(__DIR__));
$auth = new AdminAuth($storageDir . '/admin.sqlite');

try {
    $existed = $auth->hasUsers();
    $auth->createOrResetUser($username, $password);
} catch (Throwable $e) {
    fwrite(STDERR, 'admin-user: ' . $e->getMessage() . "\n");
    exit(1);
}

fwrite(STDERR, sprintf(
    "admin-user: %s operator '%s' (admin.sqlite in %s)\n",
    $existed ? 'reset' : 'created',
    $username,
    $storageDir
));
