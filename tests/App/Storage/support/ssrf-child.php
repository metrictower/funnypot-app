<?php

declare(strict_types=1);

// A worker process for SsrfStoreConcurrencyTest. Modes:
//   store <db> <n>        run n account transactions that each add one delivery-shaped entry
//   index <db> <steps>    run up to <steps> key-index advance() calls
// Prints one JSON line with what it did.

require dirname(__DIR__, 4) . '/vendor/autoload.php';

use Funnypot\App\Storage\SsrfKeyIndex;
use Funnypot\App\Storage\SsrfOutcome;
use Funnypot\App\Storage\SsrfStore;
use Funnypot\App\Storage\SsrfTx;
use Funnypot\App\Tarpit\Ssrf\KeyIndexBuilder;
use Funnypot\App\Tarpit\Ssrf\SsrfState;

[, $mode, $db, $n] = $argv + [null, '', '', '0'];
$ok = 0;
$failed = 0;
if ($mode === 'store') {
    $store = new SsrfStore($db);
    for ($i = 0; $i < (int) $n; $i++) {
        $r = $store->transact('shared-owner', 'src-' . getmypid(), 1000, static function (?SsrfState $s, SsrfTx $tx): SsrfOutcome {
            $s ??= SsrfState::fresh(1000);
            $s->d['hn'] = (int) $s->d['hn'] + 1;

            return new SsrfOutcome($s, true, 4, null);
        });
        $r['ok'] ? $ok++ : $failed++;
    }
} elseif ($mode === 'index') {
    $idx = new SsrfKeyIndex($db, 'idx-key', new KeyIndexBuilder(4242, 'fs', 1 << 20), SsrfKeyIndex::deployId('idx-key', 4242, 1 << 20, false, 'b'));
    for ($i = 0; $i < (int) $n && !$idx->complete(); $i++) {
        $idx->advance(1000);
    }
    $ok = $idx->slicesRun;
    $failed = $idx->busySkipped ? 1 : 0;
}
echo json_encode(['ok' => $ok, 'failed' => $failed]), "\n";
