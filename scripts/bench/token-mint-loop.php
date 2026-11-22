#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Scripted mint-and-use loop against the token-mint surface, in a throwaway temp directory.
 * Usage: php scripts/bench/token-mint-loop.php [profile|all] [steps=300] [seeds=5]
 * Profiles: fast, slow, cookie-drop, zero-think. Prints one JSON report line per profile and seed:
 * the friction histogram, the largest kind share, the shortest exact period, mints, authenticated
 * API calls, goal-endpoint 2xx and goal-proof bytes (both must be 0), the first friction after each
 * cookie loss, and a replay hash (identical for the same profile and seed).
 */
$root = dirname(__DIR__, 2);
require $root . '/vendor/autoload.php';
require_once $root . '/demo/lib/geo.php';
require $root . '/scripts/support/TokenMintLoop.php';

use Funnypot\App\Bench\TokenMintLoop;

$which = $argv[1] ?? 'all';
$steps = max(1, (int) ($argv[2] ?? 300));
$seeds = max(1, (int) ($argv[3] ?? 5));
$profiles = $which === 'all' ? TokenMintLoop::PROFILES : [$which];
$exit = 0;
foreach ($profiles as $profile) {
    for ($seed = 1; $seed <= $seeds; $seed++) {
        $loop = new TokenMintLoop($profile, $seed);
        try {
            $r = $loop->run($steps);
        } finally {
            $loop->cleanup();
        }
        unset($r['outcomes'], $r['stored_history']);
        echo json_encode(['profile' => $profile, 'seed' => $seed] + $r, JSON_UNESCAPED_SLASHES), "\n";
        if ($r['goal_2xx'] > 0 || $r['goal_proof_bytes'] > 0 || $r['admin_roles'] > 0 || $r['sso_successes'] > 0 || $r['max_status'] >= 500) {
            $exit = 1;
        }
    }
}
exit($exit);
