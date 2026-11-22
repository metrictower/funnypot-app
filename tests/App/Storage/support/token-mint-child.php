<?php

declare(strict_types=1);

// Token-mint concurrency worker: waits for a shared start barrier, then runs one decoy action many
// times against a shared token-mint.sqlite and prints one JSON fact line. Driven by
// TokenMintStoreConcurrencyTest. Deterministic key, persona and clock, so every worker addresses the
// same source row and the same code or refresh token.

use Funnypot\App\Storage\TokenMintStore;
use Funnypot\App\Tarpit\Mint\TokenMintDecoy;
use Funnypot\Core\RequestContext;

require dirname(__DIR__, 4) . '/vendor/autoload.php';

[, $dbPath, $action, $barrier, $arg] = $argv + [null, '', '', '', ''];
$args = json_decode((string) $arg, true) ?: [];
$now = (int) ($args['now'] ?? 1763800000);
$decoy = TokenMintDecoy::build(str_repeat("\x42", 32), (int) $args['seed'], new TokenMintStore($dbPath, (array) ($args['limits'] ?? [])), false, null, static fn (): int => $now, static function (): void {
});
$deadline = microtime(true) + 10;
while (!is_file($barrier) && microtime(true) < $deadline) {
    usleep(500);
}

$facts = ['ok' => 0, 'fail' => 0, 'other' => 0, 'tokens' => []];
$list = $action === 'exchange-list' ? (array) $args['codes'] : ($action === 'refresh-list' ? (array) $args['refreshes'] : []);
$rounds = $list !== [] ? count($list) : (int) ($args['rounds'] ?? 1);
for ($i = 0; $i < $rounds; $i++) {
    if ($action === 'exchange-list') {
        $args['code'] = $list[$i];
    } elseif ($action === 'refresh-list') {
        $args['refresh'] = $list[$i];
    }
    $headers = ['Content-Type' => 'application/x-www-form-urlencoded'];
    if (isset($args['cookie'])) {
        $headers['Cookie'] = 'session=' . $args['cookie'];
    }
    switch ($action) {
        case 'exchange-list':
        case 'refresh-list':
            $fields = $action === 'exchange-list'
                ? ['grant_type' => 'authorization_code', 'code' => $args['code'], 'client_id' => $args['client'], 'client_secret' => $args['secret']]
                : ['grant_type' => 'refresh_token', 'refresh_token' => $args['refresh'], 'client_id' => $args['client'], 'client_secret' => $args['secret']];
            $p = $decoy->prepare(new RequestContext('POST', '/login/oauth/access_token', '', $headers, http_build_query($fields)), (string) $args['ip']);
            $body = json_decode((string) $p?->body, true);
            if (isset($body['access_token'])) {
                $facts['ok']++;
                $facts['tokens'][] = $body['access_token'];
            } elseif (($body['error'] ?? null) === 'invalid_grant') {
                $facts['fail']++;
            } else {
                $facts['other']++;
            }
            break;
        case 'mint':
            $fields = ['csrf_token' => $args['csrf'], 'note' => 'w' . getmypid() . '-' . $i, 'expiration' => '30', 'scopes' => ['read:user']];
            $p = $decoy->prepare(new RequestContext('POST', '/settings/tokens', '', $headers, http_build_query($fields)), (string) $args['ip']);
            if ($p !== null && $p->status === 303 && $p->header('Location') === '/settings/tokens') {
                $facts['ok']++;
            } elseif ($p !== null && $p->status === 422 && preg_match('/at most \\d+ active tokens/', $p->body) === 1) {
                $facts['fail']++;
            } else {
                $facts['other']++;
            }
            break;
        case 'join':
            $u = 'j' . substr(md5(getmypid() . '-' . $i), 0, 10);
            $fields = ['csrf_token' => $args['csrf'], 'username' => $u, 'email' => $u . '@example.com', 'password' => 'Passw0rd!x', 'password_confirmation' => 'Passw0rd!x'];
            $p = $decoy->prepare(new RequestContext('POST', '/join', '', $headers, http_build_query($fields)), (string) $args['ip']);
            if ($p !== null && $p->status === 303) {
                $facts['ok']++;
            } else {
                $facts['other']++;
                $facts['why'] ??= ($p === null ? 'null' : $p->status . ' ' . ($p->turn['outcome'] ?? ''));
            }
            $facts['tokens'][] = $u;
            break;
        default:
            fwrite(STDERR, "unknown action {$action}\n");
            exit(2);
    }
}
echo json_encode($facts), "\n";
exit(0);
