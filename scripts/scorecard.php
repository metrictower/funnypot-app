#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * FP-0352 — UHBS/UHQS self-scorecard emitter (internal measurement; mirror-not-import).
 *
 * Emits a scorecard.schema.json-SHAPED JSON (per-module A–F, Safety Gate, UHQS, grade) to STDOUT and sets a
 * CI signal via the EXIT CODE:
 *   0  pass  (δ_C == 1.0, i.e. containment >= 95, AND unauthorized_egress_leaks == 0)
 *   1  FAIL  (containment < 95 OR any egress leak)  — the loud regression/containment signal
 *   2  argument/setup error
 *
 * Usage: php scripts/scorecard.php [--evidence=path.json] [--version=v1]
 *
 * Evidence (primary input today): a JSON of per-module scores + containment + leaks + latency + findings.
 * Keys: A,B,C,E,F (0–100 floats), containment (0–100), unauthorized_egress_leaks (int),
 *       latency {p50_ms,p95_ms,p99_ms}, critical_findings, high_findings.
 * Reuse-existing-accounting (FP-0248 egress, core CI gate finding-counts, engagement-bench latency,
 * FP-0350/0351 fidelity) is NOT machine-queryable in-repo yet — a CI wrapper runs those and feeds this
 * evidence JSON; see README. FAIL-SAFE: an absent containment/egress input stays 0 → the gate FAILS (exit 1),
 * never a fabricated pass. SECURITY: this is CLI/CI/AdminAuth-only — it is NEVER a decoy route and writes NO
 * artifact under the docroot (STDOUT only), so a scanner can never read a self-grade (a decisive tell).
 */

require dirname(__DIR__) . '/vendor/autoload.php';

use Funnypot\App\Audit\UhqsScorecard;

$evidencePath = null;
$version = 'v1';
foreach (array_slice($argv, 1) as $arg) {
    if (str_starts_with($arg, '--evidence=')) {
        $evidencePath = substr($arg, 11);
    } elseif (str_starts_with($arg, '--version=')) {
        $version = substr($arg, 10);
    } else {
        fwrite(STDERR, "scorecard: unknown argument '{$arg}'\n");
        exit(2);
    }
}

$evidence = [];
if ($evidencePath !== null) {
    if (!is_file($evidencePath) || !is_readable($evidencePath)) {
        fwrite(STDERR, "scorecard: evidence file not readable: {$evidencePath}\n");
        exit(2);
    }
    $decoded = json_decode((string) file_get_contents($evidencePath), true);
    if (!is_array($decoded)) {
        fwrite(STDERR, "scorecard: evidence is not a JSON object\n");
        exit(2);
    }
    $evidence = $decoded;
}

$scorecard = UhqsScorecard::compute($evidence, gmdate('c'), $version);

// STDOUT only — never persisted under the docroot.
echo json_encode($scorecard, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";

exit(UhqsScorecard::isPass($scorecard) ? 0 : 1);
