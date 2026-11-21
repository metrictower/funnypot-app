<?php

declare(strict_types=1);

// Summarise the webshell console's attribution log (cmdi_turns in cmdi-shell.sqlite) for an A/B arm.
//
//   php scripts/bench/cmdi-turns-report.php demo/storage/cmdi-shell.sqlite [--since=UNIX_TS]

$db = $argv[1] ?? '';
if ($db === '' || !is_file($db)) {
    fwrite(STDERR, "usage: php scripts/bench/cmdi-turns-report.php <cmdi-shell.sqlite> [--since=UNIX_TS]\n");
    exit(2);
}
$since = 0;
foreach (array_slice($argv, 2) as $a) {
    if (str_starts_with($a, '--since=')) {
        $since = (int) substr($a, 8);
    }
}

$pdo = new PDO('sqlite:' . $db, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$rows = $pdo->prepare('SELECT * FROM cmdi_turns WHERE ts >= ? ORDER BY id');
$rows->execute([$since]);
$turns = $rows->fetchAll(PDO::FETCH_ASSOC);

$count = static function (string $col) use ($turns): array {
    $c = array_count_values(array_map(static fn (array $t): string => (string) $t[$col], $turns));
    arsort($c);

    return $c;
};
$run = 0;
$best = 0;
$prevK = null;
foreach ($turns as $t) {
    $run = $t['k'] === $prevK ? $run + 1 : 1;
    $prevK = $t['k'];
    $best = max($best, $run);
}

echo json_encode([
    'turns' => count($turns),
    'sources' => count($count('k')),
    'simple' => count(array_filter($turns, static fn (array $t): bool => (int) $t['simple'] === 1)),
    'compound' => count(array_filter($turns, static fn (array $t): bool => (int) $t['simple'] === 0 && $t['kind'] !== 'landing')),
    'kinds' => $count('kind'),
    'subs' => $count('sub'),
    'messages' => $count('msg_id'),
    'families' => $count('family'),
    'identities' => $count('identity'),
    'value_sources' => $count('value_source'),
    'owned_by_rule' => $count('owned_by_rule'),
    'console_rule' => $count('console_rule'),
    'delayed_turns' => count(array_filter($turns, static fn (array $t): bool => (int) $t['delay_ms'] > 0)),
    'longest_consecutive_run_one_source' => $best,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
