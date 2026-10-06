<?php

declare(strict_types=1);

/**
 * FP-0311 §2.2 — append-only guard for resources/experiments/engagement-revisions.json.
 *
 * Takes the base-ref (merge-base) ledger and the current ledger as explicit read-only inputs and permits
 * ONLY an append: every existing tuple must be present, in the same position, with byte-identical content;
 * new tuples may appear only after them, and no tuple may be reused. It FAILS CLOSED when the base ledger
 * cannot be read or parsed — a rewrite that hides the base is treated as a violation, not a pass. It does
 * NOT claim a file can detect its own Git-history rewrite; that is the base-ref mechanism's job.
 *
 * Usage (CI):  php tools/check-experiment-ledger.php <base-ledger.json> <current-ledger.json>
 * The guard logic is a pure function so unit tests can drive it with local fixtures (no network, no git).
 */

/**
 * @return array{ok:bool,reason:string}
 */
function experiment_ledger_append_ok(?string $baseJson, string $currentJson): array
{
    if ($baseJson === null) {
        return ['ok' => false, 'reason' => 'base ledger unreadable'];
    }
    $base = experiment_ledger_entries($baseJson);
    $current = experiment_ledger_entries($currentJson);
    if ($base === null) {
        return ['ok' => false, 'reason' => 'base ledger invalid'];
    }
    if ($current === null) {
        return ['ok' => false, 'reason' => 'current ledger invalid'];
    }

    if (count($current) < count($base)) {
        return ['ok' => false, 'reason' => 'tuple deleted (current shorter than base)'];
    }

    // The first N entries must equal the base entries exactly, in order.
    foreach ($base as $i => $baseEntry) {
        if (experiment_ledger_norm($baseEntry) !== experiment_ledger_norm($current[$i])) {
            return ['ok' => false, 'reason' => "existing tuple at index {$i} mutated, deleted, or reordered"];
        }
    }

    // No tuple may be reused anywhere in the current file (catches an appended tuple-reuse).
    $seen = [];
    foreach ($current as $entry) {
        $tuple = (string) ($entry['experiment_id'] ?? '?') . '@' . (string) ($entry['revision'] ?? '?');
        if (isset($seen[$tuple])) {
            return ['ok' => false, 'reason' => "duplicate tuple {$tuple}"];
        }
        $seen[$tuple] = true;
    }

    return ['ok' => true, 'reason' => 'append-only ok'];
}

/**
 * @return array<int,array<string,mixed>>|null the experiments list, or null if malformed
 */
function experiment_ledger_entries(string $json): ?array
{
    try {
        $doc = json_decode($json, true, 32, JSON_THROW_ON_ERROR);
    } catch (\JsonException) {
        return null;
    }
    if (!is_array($doc) || !isset($doc['experiments']) || !is_array($doc['experiments']) || !array_is_list($doc['experiments'])) {
        return null;
    }
    foreach ($doc['experiments'] as $e) {
        if (!is_array($e)) {
            return null;
        }
    }

    return $doc['experiments'];
}

/** Normalise an entry for comparison: recursive key-sort then canonical JSON, so formatting/key-order
 *  differences are ignored but any value change is detected. */
function experiment_ledger_norm(array $entry): string
{
    $sort = static function (&$v) use (&$sort): void {
        if (is_array($v)) {
            if (!array_is_list($v)) {
                ksort($v);
            }
            foreach ($v as &$child) {
                $sort($child);
            }
        }
    };
    $sort($entry);

    return json_encode($entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

// CLI entry point — only when executed directly, so tests may include this file for the pure function.
if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === realpath(__FILE__)) {
    if ($argc !== 3) {
        fwrite(STDERR, "usage: php tools/check-experiment-ledger.php <base-ledger.json> <current-ledger.json>\n");
        exit(2);
    }
    $basePath = $argv[1];
    $currentPath = $argv[2];
    $baseJson = is_readable($basePath) ? @file_get_contents($basePath) : false;
    $currentJson = is_readable($currentPath) ? @file_get_contents($currentPath) : false;
    if ($currentJson === false) {
        fwrite(STDERR, "FAIL: current ledger unreadable: {$currentPath}\n");
        exit(1);
    }
    $result = experiment_ledger_append_ok($baseJson === false ? null : $baseJson, $currentJson);
    if (!$result['ok']) {
        fwrite(STDERR, "FAIL: {$result['reason']}\n");
        exit(1);
    }
    fwrite(STDOUT, "OK: {$result['reason']}\n");
    exit(0);
}
