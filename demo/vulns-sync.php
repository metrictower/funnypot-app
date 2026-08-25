<?php

declare(strict_types=1);

/**
 * Materialize / refresh the emulation toggle list from the compiled catalog — the demo's
 * vendor-free equivalent of `bin/funnypot vulns:sync` (no symfony/yaml needed; the catalog is
 * already compiled into the image). Run on container boot: new capabilities auto-appear at their
 * default, and the operator's existing on/off choices are preserved. The dashboard and the
 * protocol listeners read the resulting funnypot-vulns.json.
 */

require __DIR__ . '/../vendor/autoload.php';

use Funnypot\App\Emulation\EmulationCatalog;
use Funnypot\App\Emulation\EmulationPolicy;

$out = getenv('FUNNYPOT_VULNS') ?: __DIR__ . '/storage/funnypot-vulns.json';

$catalog = EmulationCatalog::fromPackage();
if ($catalog->count() === 0) {
    fwrite(STDERR, "vulns-sync: no compiled catalog (run `funnypot compile-catalog` at build time)\n");
    exit(0);
}

$policy = EmulationPolicy::fromCatalog($catalog, is_file($out) ? $out : null);
$vulns = $policy->materialize();

$payload = [
    'version' => 1,
    'updated' => gmdate('c'),
    'note' => 'Toggle which emulations funnypot serves. New capabilities auto-appear here at their default; true = serve, false = off.',
    'vulns' => $vulns,
];

@mkdir(dirname($out), 0777, true);
if (@file_put_contents($out, json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n") === false) {
    fwrite(STDERR, "vulns-sync: could not write {$out}\n");
    exit(0);
}
fwrite(STDERR, 'vulns-sync: ' . count($vulns) . " emulations -> {$out}\n");
