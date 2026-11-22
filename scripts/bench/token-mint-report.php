#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Read-only summary of a token-mint store's attribution table and the hit store's surface rows.
 * Usage: php scripts/bench/token-mint-report.php <token-mint.sqlite> [hits.sqlite]
 * Opens both files read-only; prints routes, outcomes, friction kinds and token kinds as JSON.
 */
$mint = $argv[1] ?? '';
$hits = $argv[2] ?? '';
if ($mint === '' || !is_file($mint)) {
    fwrite(STDERR, "usage: token-mint-report.php <token-mint.sqlite> [hits.sqlite]\n");
    exit(2);
}
$db = new PDO('sqlite:file:' . $mint . '?mode=ro', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$count = static fn (PDO $d, string $col): array => $d->query("SELECT {$col} AS k, COUNT(*) AS n FROM mint_turns GROUP BY {$col} ORDER BY n DESC")->fetchAll(PDO::FETCH_KEY_PAIR);
$out = [
    'turns' => (int) $db->query('SELECT COUNT(*) FROM mint_turns')->fetchColumn(),
    'sources' => (int) $db->query('SELECT COUNT(DISTINCT k8) FROM mint_turns')->fetchColumn(),
    'routes' => $count($db, 'route'),
    'outcomes' => $count($db, 'outcome'),
    'friction' => $count($db, 'friction'),
    'token_kinds' => $count($db, 'kind'),
    'rows' => (int) $db->query('SELECT COUNT(*) FROM mint_state')->fetchColumn(),
];
if ($hits !== '' && is_file($hits)) {
    $h = new PDO('sqlite:file:' . $hits . '?mode=ro', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $out['hits_matched'] = (int) $h->query("SELECT COUNT(*) FROM hits WHERE matched = 1 AND (path LIKE '/settings/%' OR path LIKE '/api/v2/%' OR path LIKE '/v2/%' OR path LIKE '/login/oauth/%' OR path LIKE '/join%' OR path LIKE '/idp/%' OR path LIKE '/orgs/%')")->fetchColumn();
}
echo json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
