<?php

declare(strict_types=1);

// Scripted variant-exhaustion sweep against the webshell console, through the real request pipeline.
// Runs locally (no Docker, no network). Prints one JSON object per catalog.
//
//   php scripts/bench/cmdi-syntax-sweep.php --seed 7 --steps 200 --identity auto [--catalog default|lab]

require dirname(__DIR__, 2) . '/vendor/autoload.php';

use Funnypot\Tests\Bench\CmdiSyntaxSweep;

$opts = getopt('', ['seed:', 'steps:', 'identity:', 'catalog:']);
$seed = (int) ($opts['seed'] ?? 1);
$steps = max(1, min(5000, (int) ($opts['steps'] ?? 200)));
$identity = in_array($opts['identity'] ?? 'auto', ['auto', 'www-data', 'root'], true) ? ($opts['identity'] ?? 'auto') : 'auto';
$catalogs = isset($opts['catalog']) ? [(string) $opts['catalog']] : ['default', 'lab'];

foreach ($catalogs as $catalog) {
    echo json_encode(CmdiSyntaxSweep::run($seed, $steps, $catalog, $identity), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
}
