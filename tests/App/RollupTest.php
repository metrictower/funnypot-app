<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\Storage\SqliteHitStore;
use PDO;
use PDOException;
use PHPUnit\Framework\TestCase;

/**
 * The FP-0243a rollup aggregation layer: the background fold worker (foldRollups) and the
 * O(buckets) analytics read API (breakdown/series/topN/ataglance) on SqliteHitStore.
 *
 * Covers the plan's V1-V8: rollup correctness, additive status counters, exactly-once watermark +
 * crash rollback, minute->hour->day downsampling, retention pruning, the cardinality cap, the
 * load-shaped flat-query proof, and cross-connection correctness.
 */
final class RollupTest extends TestCase
{
    /** @var string[] */
    private array $tmp = [];

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->tmp as $f) {
            foreach (['', '-wal', '-shm'] as $suf) {
                @unlink($f . $suf);
            }
        }
        $this->tmp = [];
    }

    private function dbPath(): string
    {
        $p = sys_get_temp_dir() . '/fp_rollup_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    /** A store with generous retention by default so pruning never interferes with a correctness
     *  assertion; V5/V6 pass explicit tight knobs. */
    private function newStore(
        string $path,
        int $topK = 20,
        int $retMinH = 100000,
        int $retHourD = 100000,
        int $retDayD = 100000,
    ): SqliteHitStore {
        return new SqliteHitStore($path, null, $topK, $retMinH, $retHourD, $retDayD);
    }

    /** A second raw connection to the same file — for reference GROUP BYs and cross-connection seeds. */
    private function pdo(string $path): PDO
    {
        $db = new PDO('sqlite:' . $path, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $db->exec('PRAGMA busy_timeout=3000');
        $db->exec('PRAGMA journal_mode=WAL');

        return $db;
    }

    /** @param array<string,mixed> $over */
    private function hit(string $ts, array $over = []): array
    {
        return $over + [
            'ts' => $ts,
            'ip' => '1.1.1.1',
            'method' => 'HTTP',
            'event' => 'connect',
            'severity' => 'low',
            'matched' => false,
            'served' => false,
            'geo' => ['cc' => ($over['cc'] ?? 'US')],
        ];
    }

    /** SUM(n) over a (dim,gran) slice, read straight from the rollup table. */
    private function sumN(PDO $db, string $dim, string $gran): int
    {
        $st = $db->prepare('SELECT COALESCE(SUM(n),0) FROM rollup WHERE dim=:d AND gran=:g');
        $st->execute([':d' => $dim, ':g' => $gran]);

        return (int) $st->fetchColumn();
    }

    // --- V1: rollup correctness (per-dim, per-value counts match a raw reference) ---

    public function test_v1_rollup_counts_match_raw_group_by(): void
    {
        $path = $this->dbPath();
        $store = $this->newStore($path);
        $ts = gmdate('c', time() - 120); // recent, one minute bucket, never pruned

        // A hand-built set with known dimensions.
        $store->append($this->hit($ts, ['method' => 'HTTP', 'event' => 'scan', 'severity' => 'high', 'cc' => 'US', 'tool' => 'nuclei', 'matched' => true, 'served' => true]));
        $store->append($this->hit($ts, ['method' => 'HTTP', 'event' => 'scan', 'severity' => 'high', 'cc' => 'US', 'tool' => 'nuclei', 'matched' => true, 'served' => false]));
        $store->append($this->hit($ts, ['method' => 'SIP', 'event' => 'call', 'severity' => 'low', 'cc' => 'DE', 'tool' => 'sipvicious']));
        $store->append($this->hit($ts, ['method' => 'SSH', 'event' => 'command', 'severity' => 'medium', 'cc' => 'CN', 'tool' => '']));
        $store->append($this->hit($ts, ['method' => 'SSH', 'event' => 'command', 'severity' => 'medium', 'cc' => 'CN', 'tool' => '']));
        $store->append($this->hit($ts, ['method' => 'SSH', 'event' => 'connect', 'severity' => 'low', 'cc' => '', 'tool' => 'masscan', 'known_attacker' => true]));

        self::assertSame(6, $store->foldRollups(1000));

        $db = $this->pdo($path);

        // For each column-backed dim, the rollup's per-value counts equal a raw GROUP BY (empties skipped).
        $map = ['protocol' => 'method', 'event' => 'event', 'severity' => 'severity', 'country' => 'cc', 'tool' => 'tool'];
        foreach ($map as $dim => $col) {
            $ref = [];
            foreach ($db->query("SELECT $col v, COUNT(*) n FROM hits WHERE $col<>'' GROUP BY $col") as $r) {
                $ref[(string) $r['v']] = (int) $r['n'];
            }
            $got = [];
            $st = $db->prepare("SELECT val, n FROM rollup WHERE dim=:d AND gran='m'");
            $st->execute([':d' => $dim]);
            foreach ($st as $r) {
                $got[(string) $r['val']] = (int) $r['n'];
            }
            self::assertEquals($ref, $got, "dim=$dim per-value counts must match the raw GROUP BY");
            self::assertSame(array_sum($ref), $this->sumN($db, $dim, 'm'), "dim=$dim total must match COUNT(*)");
        }

        // dim='total' counts every event; dim='status' partitions every event.
        self::assertSame(6, $this->sumN($db, 'total', 'm'));
        self::assertSame(6, $this->sumN($db, 'status', 'm'));
        $status = [];
        $st = $db->query("SELECT val, n FROM rollup WHERE dim='status' AND gran='m'");
        foreach ($st as $r) {
            $status[(string) $r['val']] = (int) $r['n'];
        }
        // known_attacker (1) > matched (2) > served (0 remaining) > none: rows 1,2 matched; row6 known; 3,4,5 none.
        self::assertEqualsCanonicalizing(['matched' => 2, 'known_attacker' => 1, 'none' => 3], $status);
    }

    // --- V2: additive matched/served counters ---

    public function test_v2_matched_served_counters_are_additive(): void
    {
        $path = $this->dbPath();
        $store = $this->newStore($path);
        $ts = gmdate('c', time() - 120);
        $store->append($this->hit($ts, ['method' => 'HTTP', 'matched' => true, 'served' => true]));
        $store->append($this->hit($ts, ['method' => 'HTTP', 'matched' => true, 'served' => false]));
        $store->append($this->hit($ts, ['method' => 'SIP', 'matched' => false, 'served' => true]));
        $store->foldRollups(1000);

        $db = $this->pdo($path);
        $rawM = (int) $db->query('SELECT COALESCE(SUM(matched),0) FROM hits')->fetchColumn();
        $rawS = (int) $db->query('SELECT COALESCE(SUM(served),0) FROM hits')->fetchColumn();
        self::assertSame(2, $rawM);
        self::assertSame(2, $rawS);

        foreach (['total', 'protocol'] as $dim) {
            $r = $db->query("SELECT COALESCE(SUM(matched),0) m, COALESCE(SUM(served),0) s FROM rollup WHERE dim='$dim' AND gran='m'")->fetch(PDO::FETCH_ASSOC);
            self::assertSame($rawM, (int) $r['m'], "matched must sum over dim=$dim");
            self::assertSame($rawS, (int) $r['s'], "served must sum over dim=$dim");
        }
    }

    // --- V3: exactly-once watermark + crash rollback ---

    public function test_v3_exactly_once_watermark(): void
    {
        $path = $this->dbPath();
        $store = $this->newStore($path);
        $ts = gmdate('c', time() - 120);
        $store->append($this->hit($ts));
        $store->append($this->hit($ts));

        self::assertSame(2, $store->foldRollups(1000));
        $db = $this->pdo($path);
        self::assertSame(2, $this->sumN($db, 'total', 'm'));
        self::assertSame('2', $db->query("SELECT v FROM rollup_state WHERE k='last_id'")->fetchColumn());

        // Re-fold with no new rows: no-op, no double count.
        self::assertSame(0, $store->foldRollups(1000));
        self::assertSame(2, $this->sumN($db, 'total', 'm'));

        // Append more, fold: only the new rows are added and the watermark advances.
        $store->append($this->hit($ts));
        self::assertSame(1, $store->foldRollups(1000));
        self::assertSame(3, $this->sumN($db, 'total', 'm'));
        self::assertSame('3', $db->query("SELECT v FROM rollup_state WHERE k='last_id'")->fetchColumn());
    }

    public function test_v3_aborted_pass_rolls_back_and_reprocesses_cleanly(): void
    {
        $path = $this->dbPath();
        $store = $this->newStore($path);
        $ts = gmdate('c', time() - 120);
        $store->append($this->hit($ts));
        $store->foldRollups(1000); // baseline: 1 event folded, last_id=1

        $db = $this->pdo($path);
        $baseN = $this->sumN($db, 'total', 'm');
        $baseLast = (string) $db->query("SELECT v FROM rollup_state WHERE k='last_id'")->fetchColumn();

        // A new unfolded hit, then a second connection grabs the write lock so the fold cannot commit.
        $store->append($this->hit($ts));
        $lock = $this->pdo($path);
        $lock->exec('BEGIN IMMEDIATE');
        try {
            $store->foldRollups(1000);
            self::fail('foldRollups should have failed while another connection held the write lock');
        } catch (PDOException $e) {
            // expected: the write blocked past busy_timeout
        }

        // The aborted pass left nothing behind: totals and watermark are exactly the baseline.
        self::assertSame($baseN, $this->sumN($db, 'total', 'm'), 'rollup counts must be unchanged after a rolled-back pass');
        self::assertSame($baseLast, (string) $db->query("SELECT v FROM rollup_state WHERE k='last_id'")->fetchColumn(), 'watermark must not advance on a rolled-back pass');

        // Release the lock; the next clean pass reprocesses the same rows with no double count.
        $lock->exec('ROLLBACK');
        self::assertSame(1, $store->foldRollups(1000));
        self::assertSame($baseN + 1, $this->sumN($db, 'total', 'm'));
    }

    /**
     * Two folds racing over the same freshly-seeded batch (e.g. an operator running
     * `php demo/rollup.php` by hand while the entrypoint timer loop also runs) must NOT double-count.
     * A real second process folds the same DB in lockstep with an in-process fold, gated on a
     * filesystem barrier so they start together. With foldRollups taking the write lock (BEGIN
     * IMMEDIATE) before reading the watermark, the two serialize and the loser reads the advanced
     * watermark → no rows to re-fold; the final totals equal the raw COUNT. (Without that fix both
     * read last_id=0 outside any transaction and both commit n=n+delta → a permanent 2x double
     * count — this test then fails.)
     */
    public function test_v3_concurrent_folds_do_not_double_count(): void
    {
        if (!function_exists('proc_open')) {
            self::markTestSkipped('proc_open unavailable');
        }
        $path = $this->dbPath();
        $store = $this->newStore($path);           // creates the schema
        $n = 8000;                                  // big enough that a fold's window overlaps a racer,
        $this->fastSeed($path, $n);                 // small enough to finish well under busy_timeout

        $autoload = dirname(__DIR__, 2) . '/vendor/autoload.php';
        $child = $path . '.child.php';
        $ready = $path . '.ready';
        $go = $path . '.go';
        $this->tmp[] = $child;
        $this->tmp[] = $ready;
        $this->tmp[] = $go;
        file_put_contents($child, "<?php\n"
            . "require " . var_export($autoload, true) . ";\n"
            . "use Funnypot\\App\\Storage\\SqliteHitStore;\n"
            . "\$s = new SqliteHitStore(" . var_export($path, true) . ");\n"
            . "touch(" . var_export($ready, true) . ");\n"
            . "while (!file_exists(" . var_export($go, true) . ")) { usleep(200); }\n"
            . "try { while (\$s->foldRollups(100000) > 0) {} } catch (\\Throwable \$e) { fwrite(STDERR, \$e->getMessage()); }\n");

        $proc = proc_open([PHP_BINARY, $child], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        self::assertIsResource($proc);
        // Wait for the child to boot and reach the barrier, then release both at once.
        $deadline = microtime(true) + 10;
        while (!file_exists($ready) && microtime(true) < $deadline) {
            usleep(500);
        }
        self::assertFileExists($ready, 'child fold process failed to start');
        touch($go);
        try {
            while ($store->foldRollups(100000) > 0) {
                // drain
            }
        } catch (\Throwable $e) {
            // a busy-timeout on the loser is acceptable; the guarantee under test is "no double count"
        }
        foreach ($pipes as $p) {
            @stream_get_contents($p);
            @fclose($p);
        }
        proc_close($proc); // blocks until the child exits

        $db = $this->pdo($path);
        self::assertSame($n, (int) $db->query('SELECT COUNT(*) FROM hits')->fetchColumn());
        self::assertSame($n, $this->sumN($db, 'total', 'm'), 'concurrent folds must not double-count (minute)');
        self::assertSame($n, $this->sumN($db, 'total', 'd'), 'concurrent folds must not double-count (day)');
        self::assertSame((string) $n, (string) $db->query("SELECT v FROM rollup_state WHERE k='last_id'")->fetchColumn());
    }

    /** Fast batched raw insert of $n synthetic hits over ~1440 recent minute buckets (no per-row
     *  append()); used to seed a fold batch without folding it. */
    private function fastSeed(string $path, int $n): void
    {
        $db = $this->pdo($path);
        $protocols = ['HTTP', 'SSH', 'SIP', 'RDP', 'TELNET'];
        $now = time();
        $span = 1440;
        $start = $now - $span * 60;
        $cols = '(ts,ip,method,path,matched,severity,served,templates,body,event,cc,tool)';
        $rowsql = '(?,?,?,?,?,?,?,?,?,?,?,?)';
        $chunk = 200;
        $wide = $db->prepare("INSERT INTO hits $cols VALUES " . implode(',', array_fill(0, $chunk, $rowsql)));
        $db->beginTransaction();
        $buf = [];
        $c = 0;
        for ($i = 0; $i < $n; $i++) {
            $ts = gmdate('c', $start + ($i % $span) * 60);
            array_push($buf, $ts, '1.2.3.' . ($i % 254), $protocols[$i % 5], '/p' . ($i % 50), 0, 'low', 0, '[]', '', 'connect', 'US', '');
            if (++$c === $chunk) {
                $wide->execute($buf);
                $buf = [];
                $c = 0;
            }
        }
        if ($c > 0) {
            $db->prepare("INSERT INTO hits $cols VALUES " . implode(',', array_fill(0, $c, $rowsql)))->execute($buf);
        }
        $db->commit();
    }

    // --- V4: minute -> hour -> day downsampling is loss/dupe free ---

    public function test_v4_downsampling_totals_agree_across_granularities(): void
    {
        $path = $this->dbPath();
        $store = $this->newStore($path);
        $now = time();
        // Spread events across several minutes and hours (all recent, within retention).
        $n = 0;
        foreach ([0, 90, 3700, 7300, 7360] as $ago) { // 2 in one hour, then later hours
            foreach (['HTTP', 'SIP'] as $proto) {
                $store->append($this->hit(gmdate('c', $now - $ago), ['method' => $proto]));
                $n++;
            }
        }
        $folded = 0;
        while (($k = $store->foldRollups(3)) > 0) { // small batch to exercise multi-pass folding
            $folded += $k;
        }
        self::assertSame($n, $folded);

        $db = $this->pdo($path);
        $raw = (int) $db->query('SELECT COUNT(*) FROM hits')->fetchColumn();
        // The same events, counted once at each granularity: minute == hour == day == raw.
        self::assertSame($raw, $this->sumN($db, 'total', 'm'));
        self::assertSame($raw, $this->sumN($db, 'total', 'h'));
        self::assertSame($raw, $this->sumN($db, 'total', 'd'));
        // And per protocol.
        foreach (['HTTP', 'SIP'] as $proto) {
            $perGran = [];
            foreach (['m', 'h', 'd'] as $g) {
                $st = $db->prepare("SELECT COALESCE(SUM(n),0) FROM rollup WHERE dim='protocol' AND gran=:g AND val=:v");
                $st->execute([':g' => $g, ':v' => $proto]);
                $perGran[$g] = (int) $st->fetchColumn();
            }
            self::assertSame($perGran['m'], $perGran['h'], "$proto minute total must equal hour total");
            self::assertSame($perGran['m'], $perGran['d'], "$proto minute total must equal day total");
        }
    }

    // --- V5: retention prunes fine buckets but keeps the coarse rollup ---

    public function test_v5_retention_prunes_minutes_but_preserves_days(): void
    {
        $path = $this->dbPath();
        // Minute buckets kept 1h; hour + day kept effectively forever.
        $store = $this->newStore($path, 20, 1, 100000, 100000);
        $now = time();
        $oldTs = gmdate('c', $now - 3 * 3600);       // 3h old: past the 1h minute retention
        $newTs = gmdate('c', $now - 120);            // recent: within retention
        $oldBucket = ($now - 3 * 3600);
        $oldMinBucket = $oldBucket - ($oldBucket % 60);

        for ($i = 0; $i < 5; $i++) {
            $store->append($this->hit($oldTs));
        }
        for ($i = 0; $i < 4; $i++) {
            $store->append($this->hit($newTs));
        }
        $store->foldRollups(1000);

        $db = $this->pdo($path);
        // The old minute bucket was pruned; only the 4 recent events remain at minute grain.
        $st = $db->prepare("SELECT COUNT(*) FROM rollup WHERE gran='m' AND bucket=:b AND dim='total'");
        $st->execute([':b' => $oldMinBucket]);
        self::assertSame(0, (int) $st->fetchColumn(), 'the old minute bucket must be pruned');
        self::assertSame(4, $this->sumN($db, 'total', 'm'), 'only recent minute buckets survive');

        // But the day rollup still holds all 9 events — downsampling kept the history retention dropped.
        self::assertSame(9, $this->sumN($db, 'total', 'd'), 'the day rollup must preserve pruned minute history');

        // Prove the day total is folded INCREMENTALLY, not recomputed from the (now-pruned) minute
        // rows: append one more recent hit, re-fold, and the day total must tick 9 -> 10. If the
        // fold recomputed the day bucket by re-reading minute rows, the pruned 5 old events would be
        // lost and the day total would come back wrong (6, not 10).
        $store->append($this->hit(gmdate('c', $now - 60)));
        $store->foldRollups(1000);
        // Fresh read connection: the $db handle above holds an open WAL read snapshot (a fully-read
        // but unfinalised statement), so it would not see this new commit. A real reader opens fresh.
        $db2 = $this->pdo($path);
        self::assertSame(10, $this->sumN($db2, 'total', 'd'), 'day total must increment incrementally, not recompute from pruned minutes');
        self::assertSame(5, $this->sumN($db2, 'total', 'm'), 'the recent minute buckets carry the 4 + 1 recent events');
    }

    // --- V6: cardinality cap bounds a sprayed dimension ---

    public function test_v6_topk_cap_folds_the_tail_into_other(): void
    {
        $path = $this->dbPath();
        $k = 5;
        $store = $this->newStore($path, $k);
        $ts = gmdate('c', time() - 120);

        // 10 distinct tools in one minute bucket, tool i appearing (10 - i) times (all distinct counts).
        $total = 0;
        for ($i = 0; $i < 10; $i++) {
            $count = 10 - $i; // t0:10 ... t9:1
            for ($j = 0; $j < $count; $j++) {
                $store->append($this->hit($ts, ['method' => 'HTTP', 'tool' => 'tool' . $i]));
                $total++;
            }
        }
        $store->foldRollups(1000);

        $db = $this->pdo($path);
        $rows = $db->query("SELECT val, n FROM rollup WHERE dim='tool' AND gran='m'")->fetchAll(PDO::FETCH_KEY_PAIR);
        // At most K + 1 rows (top-K plus the single '(other)').
        self::assertLessThanOrEqual($k + 1, count($rows), 'a sprayed dimension must stay bounded to K+1 rows');
        self::assertArrayHasKey('(other)', $rows);
        // Top-5 kept verbatim: tool0..tool4 with counts 10..6.
        foreach (range(0, 4) as $i) {
            self::assertSame(10 - $i, (int) $rows['tool' . $i]);
        }
        // '(other)' == summed tail (tool5..tool9 => 5+4+3+2+1 = 15).
        self::assertSame(15, (int) $rows['(other)']);
        // Total count preserved despite the fold.
        self::assertSame($total, array_sum(array_map('intval', $rows)));
        self::assertSame($total, $this->sumN($db, 'total', 'm'));
    }

    // --- read API shapes (breakdown / series / topN / ataglance) ---

    public function test_read_api_breakdown_series_topn_ataglance(): void
    {
        $path = $this->dbPath();
        $store = $this->newStore($path);
        $now = time();
        $b0 = $now - ($now % 60);
        // Two minute buckets, three protocols with known counts.
        $store->append($this->hit(gmdate('c', $now - 120), ['method' => 'HTTP', 'ip' => '9.0.0.1', 'path' => '/a']));
        $store->append($this->hit(gmdate('c', $now - 120), ['method' => 'HTTP', 'ip' => '9.0.0.1', 'path' => '/a']));
        $store->append($this->hit(gmdate('c', $now - 120), ['method' => 'SIP', 'ip' => '9.0.0.2', 'path' => '/b']));
        $store->append($this->hit(gmdate('c', $now - 60), ['method' => 'HTTP', 'ip' => '9.0.0.3', 'path' => '/a']));
        $store->foldRollups(1000);

        // breakdown: ordered by n desc.
        $bd = $store->breakdown('protocol', $now - 3600, 'm');
        self::assertSame('HTTP', $bd[0]['val']);
        self::assertSame(3, $bd[0]['n']);
        self::assertSame('SIP', $bd[1]['val']);
        self::assertSame(1, $bd[1]['n']);

        // series: keyed by value, buckets ascending.
        $ser = $store->series('protocol', ['HTTP', 'SIP'], $now - 3600, 'm');
        self::assertArrayHasKey('HTTP', $ser);
        self::assertArrayHasKey('SIP', $ser);
        self::assertSame(3, array_sum(array_column($ser['HTTP'], 'n')));
        foreach ($ser['HTTP'] as $pt) {
            self::assertArrayHasKey('bucket', $pt);
            self::assertArrayHasKey('n', $pt);
        }
        self::assertSame([], $store->series('protocol', [], $now - 3600, 'm')); // empty vals => empty

        // topN over the raw table (retention-bounded, high cardinality).
        $paths = $store->topN('path', 5, $now - 3600);
        self::assertSame('/a', $paths[0]['val']);
        self::assertSame(3, $paths[0]['n']);
        self::assertSame([], $store->topN('not_a_dim', 5, $now - 3600)); // non-whitelisted => empty

        // ataglance: rate from minute rollups; unique IPs raw.
        $ag = $store->ataglance(3600);
        self::assertSame(3600, $ag['window_s']);
        self::assertSame(4, $ag['events']);
        self::assertSame(3, $ag['unique_ips']);
        self::assertArrayHasKey('new', $ag);
        self::assertArrayHasKey('returning', $ag);
        self::assertEqualsWithDelta(4 / 3600, $ag['rate'], 0.0001);
    }

    public function test_ataglance_new_vs_returning(): void
    {
        $path = $this->dbPath();
        $store = $this->newStore($path);
        $now = time();
        // A returning IP: seen both before and within the window.
        $store->append($this->hit(gmdate('c', $now - 7200), ['ip' => '5.5.5.5'])); // before window
        $store->append($this->hit(gmdate('c', $now - 60), ['ip' => '5.5.5.5']));   // within window
        // A brand-new IP: only within the window.
        $store->append($this->hit(gmdate('c', $now - 60), ['ip' => '6.6.6.6']));
        $store->foldRollups(1000);

        $ag = $store->ataglance(600); // 10-minute window
        self::assertSame(2, $ag['unique_ips']);
        self::assertSame(1, $ag['returning']);
        self::assertSame(1, $ag['new']);
    }

    // --- V8: cross-connection correctness (WAL guarantee) ---

    public function test_v8_worker_sees_rows_from_another_connection(): void
    {
        $path = $this->dbPath();
        $writer = $this->newStore($path); // opens/creates the schema
        $other = $this->newStore($path);  // a second, independent connection to the same file
        $ts = gmdate('c', time() - 120);

        // Interleave appends from both connections.
        $writer->append($this->hit($ts, ['ip' => '1.0.0.1']));
        $other->append($this->hit($ts, ['ip' => '1.0.0.2']));
        $writer->append($this->hit($ts, ['ip' => '1.0.0.3']));
        $other->append($this->hit($ts, ['ip' => '1.0.0.4']));

        // A single fold on the writer connection must count every event, whoever wrote it.
        self::assertSame(4, $writer->foldRollups(1000));
        $db = $this->pdo($path);
        self::assertSame(4, $this->sumN($db, 'total', 'm'));
    }

    // --- V7: load-shaped flat-query proof (the hard part) ---

    public function test_v7_query_time_is_flat_in_event_volume(): void
    {
        $small = 10000;
        $large = (int) (getenv('FUNNYPOT_ROLLUP_TEST_LARGE') ?: 200000);

        [$rSmall, $rawSmall, $bdSmall] = $this->seedFoldMeasure($small);
        [$rLarge, $rawLarge, $bdLarge] = $this->seedFoldMeasure($large);

        // Both runs cover the same ~1440 minute buckets, so the rollup table is the same size
        // regardless of how many events are behind it — the O(buckets) property.
        self::assertGreaterThan(0, $rSmall['rollupRows']);
        self::assertEqualsWithDelta($rSmall['rollupRows'], $rLarge['rollupRows'], $rSmall['rollupRows'] * 0.1, 'rollup size must not scale with event volume');
        // Every seeded event was folded (nothing lost) at each scale.
        self::assertSame($small, $rSmall['totalN']);
        self::assertSame($large, $rLarge['totalN']);

        // (a) MACHINE-INDEPENDENT: breakdown time is flat between the 10k and the large seed (the
        // rollup read does not scan the hits table). Generous 4x tolerance + a 5ms slack absorbs
        // sub-millisecond timing noise; the point is it does NOT grow ~20x like the raw scan does.
        self::assertLessThan($bdSmall['breakdown'] * 4.0 + 0.005, $bdLarge['breakdown'], 'rollup breakdown time must stay flat as event volume grows');

        // (b) MACHINE-INDEPENDENT: the raw GROUP BY over hits DOES scale with volume, and at the
        // large seed it is far slower than the rollup read — i.e. the rollup removed the full-table
        // scan. (Ratios on one machine/run, not absolute budgets.)
        self::assertGreaterThan($rawSmall['rawgb'] * 3.0, $rawLarge['rawgb'], 'the raw GROUP BY must scale with event volume');
        self::assertGreaterThan($bdLarge['breakdown'] * 5.0, $rawLarge['rawgb'], 'the rollup read must be materially cheaper than the raw scan at volume');

        // (c) TOLERANT absolute budget (skippable on a slow box): one fold batch and one rollup read
        // are each quick. Bounds are deliberately loose so they pass on modest CI, per suite
        // conventions; the flat-vs-growth checks above are the machine-independent proof. Set
        // FUNNYPOT_SKIP_PERF_BUDGET to a truthy value to skip these (a bare/"0"/"" value does NOT skip).
        if (!filter_var(getenv('FUNNYPOT_SKIP_PERF_BUDGET'), FILTER_VALIDATE_BOOLEAN)) {
            self::assertLessThan(0.25, $bdLarge['breakdown'], 'a single rollup breakdown read should be well under a loose 250ms budget');
            self::assertLessThan(2.0, $rLarge['batchTime'], 'a single fold batch should be well under a loose 2s budget');
        }
    }

    /**
     * Seed $n synthetic hits over ~1440 recent minute buckets via a fast batched raw insert (never
     * append() per row), fold them all, then measure a rollup breakdown, a rollup series and a raw
     * GROUP BY.
     *
     * @return array{0:array{rollupRows:int,totalN:int,batchTime:float},1:array{rawgb:float},2:array{breakdown:float}}
     */
    private function seedFoldMeasure(int $n): array
    {
        $path = $this->dbPath();
        $store = $this->newStore($path); // generous retention: all recent buckets survive
        $db = $this->pdo($path);

        $protocols = ['HTTP', 'SSH', 'SIP', 'RDP', 'TELNET'];
        $tools = ['', 'nuclei', 'sqlmap', 'sipvicious', 'masscan'];
        $sev = ['low', 'medium', 'high', 'critical'];
        $ccs = ['US', 'CN', 'RU', 'DE', 'BR'];
        $now = time();
        $span = 1440;                 // one day of minute buckets
        $start = $now - $span * 60;

        $cols = '(ts,ip,method,path,matched,severity,served,templates,body,event,cc,tool)';
        $rowsql = '(?,?,?,?,?,?,?,?,?,?,?,?)';
        $chunk = 200;
        $wide = $db->prepare("INSERT INTO hits $cols VALUES " . implode(',', array_fill(0, $chunk, $rowsql)));
        $db->beginTransaction();
        $buf = [];
        $c = 0;
        for ($i = 0; $i < $n; $i++) {
            $ts = gmdate('c', $start + ($i % $span) * 60);
            array_push(
                $buf,
                $ts, '1.2.3.' . ($i % 254), $protocols[$i % 5], '/p' . ($i % 50),
                $i % 3 === 0 ? 1 : 0, $sev[$i % 4], $i % 2 === 0 ? 1 : 0, '[]', '',
                $i % 7 === 0 ? 'scan' : 'connect', $ccs[$i % 5], $tools[$i % 5]
            );
            if (++$c === $chunk) {
                $wide->execute($buf);
                $buf = [];
                $c = 0;
            }
        }
        if ($c > 0) {
            $db->prepare("INSERT INTO hits $cols VALUES " . implode(',', array_fill(0, $c, $rowsql)))->execute($buf);
        }
        $db->commit();

        // Fold everything; separately time one representative batch for the (c) budget.
        $t0 = microtime(true);
        $store->foldRollups(5000);
        $batchTime = microtime(true) - $t0;
        while ($store->foldRollups(5000) > 0) {
            // drain
        }

        $rollupRows = (int) $db->query('SELECT COUNT(*) FROM rollup')->fetchColumn();
        $totalN = $this->sumN($db, 'total', 'm');

        // Measure over many iterations for a stable signal.
        $iters = 50;
        $tb = microtime(true);
        for ($k = 0; $k < $iters; $k++) {
            $store->breakdown('protocol', $start, 'm');
        }
        $breakdown = (microtime(true) - $tb) / $iters;

        $tr = microtime(true);
        for ($k = 0; $k < $iters; $k++) {
            $db->query("SELECT method, COUNT(*) n FROM hits WHERE method<>'' GROUP BY method")->fetchAll();
        }
        $rawgb = (microtime(true) - $tr) / $iters;

        return [
            ['rollupRows' => $rollupRows, 'totalN' => $totalN, 'batchTime' => $batchTime],
            ['rawgb' => $rawgb],
            ['breakdown' => $breakdown],
        ];
    }
}
