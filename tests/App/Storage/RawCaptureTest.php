<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Storage;

use Funnypot\App\Storage\RawCapture;
use Funnypot\Core\RequestContext;
use PDO;
use PHPUnit\Framework\TestCase;

/**
 * Full-request capture for a vuln scan (FUNNYPOT_CAPTURE_RAW). Unlike the classified `hits` table (which
 * keeps only UA + Referer + a 300-char body slice), this stores the COMPLETE request — every header, the
 * full query string, and the full body up to a 64KB cap — so an operator can see exactly what a scanner
 * sent. Fail-open: capture must never break request handling.
 *
 * FP-0249: retention (age + size) and the WAL/legacy-vacuum disk-safety behaviour it depends on.
 */
final class RawCaptureTest extends TestCase
{
    /** @var string[] */
    private array $tmp = [];

    protected function tearDown(): void
    {
        foreach ($this->tmp as $f) {
            foreach (['', '-wal', '-shm'] as $suf) {
                @unlink($f . $suf);
            }
        }
        $this->tmp = [];
    }

    private function tmpDb(): string
    {
        $p = sys_get_temp_dir() . '/fp-raw-' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    public function test_captures_every_header_the_full_query_and_body(): void
    {
        $db = $this->tmpDb();
        $ctx = new RequestContext(
            'POST',
            '/wp-login.php',
            'a=1&b=2&redirect=/etc/passwd',
            ['User-Agent' => 'sqlmap/1.7', 'X-Forwarded-For' => '1.2.3.4', 'Authorization' => 'Bearer xyz', 'Cookie' => 'sess=deadbeef'],
            "log=admin&pwd=' OR 1=1-- -",
            'victim.test',
            'https',
            '1.1'
        );
        (new RawCapture($db))->capture($ctx, '203.0.113.9');

        $pdo = new PDO('sqlite:' . $db);
        $row = $pdo->query('SELECT * FROM raw_requests')->fetch(PDO::FETCH_ASSOC);
        self::assertSame('POST', $row['method']);
        self::assertSame('/wp-login.php', $row['path']);
        self::assertSame('a=1&b=2&redirect=/etc/passwd', $row['query'], 'full GET query captured');
        self::assertSame('203.0.113.9', $row['ip']);
        // EVERY header, not just UA/Referer.
        self::assertStringContainsString('sqlmap', $row['headers']);
        self::assertStringContainsString('X-Forwarded-For', $row['headers']);
        self::assertStringContainsString('Authorization', $row['headers']);
        self::assertStringContainsString('Cookie', $row['headers']);
        // Full body, not a 300-char slice.
        self::assertStringContainsString("OR 1=1", $row['body']);
        self::assertSame('victim.test', $row['host']);
    }

    public function test_body_is_capped_at_64kb_but_the_true_size_is_recorded(): void
    {
        $db = $this->tmpDb();
        $big = str_repeat('A', 100000); // 100KB payload
        (new RawCapture($db))->capture(new RequestContext('POST', '/x', '', [], $big), '1.1.1.1');

        $pdo = new PDO('sqlite:' . $db);
        $row = $pdo->query('SELECT length(body) bl, body_bytes FROM raw_requests')->fetch(PDO::FETCH_ASSOC);
        self::assertSame(65536, (int) $row['bl'], 'body stored capped at 64KB');
        self::assertSame(100000, (int) $row['body_bytes'], 'true byte size recorded even when the stored body is capped');
    }

    public function test_capture_never_throws_even_on_an_unwritable_path(): void
    {
        // Fail-open: a broken capture must not break the honeypot.
        (new RawCapture('/no/such/dir/raw.sqlite'))->capture(new RequestContext('GET', '/'), '1.1.1.1');
        self::assertTrue(true);
    }

    public function test_retain_days_prunes_old_rows_keeps_recent(): void
    {
        $db = $this->tmpDb();
        $rc = new RawCapture($db);
        $rc->capture(new RequestContext('GET', '/old1'), '1.1.1.1');
        $rc->capture(new RequestContext('GET', '/old2'), '1.1.1.2');
        $rc->capture(new RequestContext('GET', '/new1'), '1.1.1.3');
        $rc->capture(new RequestContext('GET', '/new2'), '1.1.1.4');

        $pdo = new PDO('sqlite:' . $db);
        $pdo->exec("UPDATE raw_requests SET ts = '2020-01-01T00:00:00+00:00' WHERE path IN ('/old1','/old2')");

        self::assertSame(2, $rc->retainDays(30), 'only the two back-dated rows are pruned');
        $remaining = $pdo->query('SELECT path FROM raw_requests ORDER BY id')->fetchAll(PDO::FETCH_COLUMN, 0);
        self::assertSame(['/new1', '/new2'], $remaining);

        self::assertSame(0, $rc->retainDays(30), 'idempotent: nothing left to prune');
    }

    /**
     * The ticket-mandated test: capture enough big requests to build a real multi-MB file, cap it well
     * under its current size, and prove retainBytes() both deletes rows AND hands the freed pages back
     * to disk (not just that rows vanish from the row count) — the whole point of routing through
     * Sqlite::open() for auto_vacuum=INCREMENTAL.
     */
    public function test_full_raw_capture_db_is_pruned_under_the_size_cap(): void
    {
        $db = $this->tmpDb();
        $rc = new RawCapture($db);
        $bigBody = str_repeat('A', 65536); // hits the 64KB cap, ~136KB/row worst case in spirit
        // 300 rows (> the 200-row retainBytes() chunk size) so a cap can leave a genuine, non-empty,
        // non-whole-table remainder to assert against.
        $total = 300;
        for ($i = 0; $i < $total; $i++) {
            $rc->capture(new RequestContext('POST', '/scan/' . $i, '', [], $bigBody), '2.2.2.2');
        }
        $rc->checkpointWal();
        $before = $rc->sizeBytes();
        self::assertGreaterThan(10 * 1024 * 1024, $before, 'sanity: the capture file should be several MB');
        // 50%, not 25%: with 300 rows and a 200-row retainBytes() chunk, a too-aggressive cap forces a
        // second chunk that drains the (now under-200-row) table entirely — 50% leaves the post-first
        // -chunk remainder (100 rows) already under cap, so the test can assert a genuine partial trim.
        $cap = (int) ($before * 0.5);

        $removed = $rc->retainBytes($cap);
        self::assertGreaterThan(0, $removed);
        self::assertLessThanOrEqual($cap, $rc->sizeBytes(), 'auto_vacuum + incremental_vacuum + checkpoint must actually hand pages back');

        $pdo = new PDO('sqlite:' . $db);
        $remainingIds = array_map('intval', $pdo->query('SELECT id FROM raw_requests ORDER BY id')->fetchAll(PDO::FETCH_COLUMN, 0));
        self::assertNotEmpty($remainingIds, 'trimmed, not drained');
        self::assertLessThan($total, count($remainingIds), 'trimmed, not left whole');
        foreach ($remainingIds as $id) {
            self::assertGreaterThan($total - count($remainingIds), $id, 'survivors are the newest ids');
        }
    }

    public function test_size_bytes_counts_the_wal_sidecar(): void
    {
        $db = $this->tmpDb();
        $rc = new RawCapture($db);
        $body = str_repeat('C', 20000);
        for ($i = 0; $i < 100; $i++) {
            $rc->capture(new RequestContext('POST', '/x', '', [], $body), '3.3.3.3');
        }

        $pdo = new PDO('sqlite:' . $db);
        $pageOnly = (int) $pdo->query('PRAGMA page_count')->fetchColumn() * (int) $pdo->query('PRAGMA page_size')->fetchColumn();

        self::assertGreaterThan($pageOnly, $rc->sizeBytes(), 'sizeBytes() must count the -wal sidecar on top of page_count*page_size');

        $rc->checkpointWal();
        clearstatcache(true, $db . '-wal');
        self::assertSame(0, (int) @filesize($db . '-wal'), '-wal truncated to 0 after checkpointWal()');
    }

    public function test_legacy_db_without_auto_vacuum_is_converted_once_then_size_reclaim_works(): void
    {
        $db = $this->tmpDb();

        // Build the db with a raw `new PDO` — today's pre-fix shape: no auto_vacuum set.
        $legacy = new PDO('sqlite:' . $db, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $legacy->exec('PRAGMA journal_mode=WAL');
        $legacy->exec(
            'CREATE TABLE IF NOT EXISTS raw_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT, ip TEXT, method TEXT, path TEXT, query TEXT,
                headers TEXT, body TEXT, body_bytes INTEGER DEFAULT 0,
                host TEXT, scheme TEXT, http_version TEXT
            )'
        );
        self::assertNotSame(2, (int) $legacy->query('PRAGMA auto_vacuum')->fetchColumn(), 'sanity: legacy db has no incremental auto_vacuum');

        $rc = new RawCapture($db);
        $body = str_repeat('D', 30000);
        for ($i = 0; $i < 100; $i++) {
            $rc->capture(new RequestContext('POST', '/y', '', [], $body), '4.4.4.4');
        }

        // capture() ALONE must NOT trigger the conversion — the VACUUM must never run in the request path.
        self::assertNotSame(2, (int) $legacy->query('PRAGMA auto_vacuum')->fetchColumn(), 'capture() must never run the legacy VACUUM');

        $rc->checkpointWal();
        $before = $rc->sizeBytes();
        $cap = (int) ($before * 0.5);
        $removed = $rc->retainBytes($cap);

        self::assertGreaterThan(0, $removed);
        // A fresh connection, not $legacy: VACUUM rewrites the file, and a long-lived connection can
        // keep a cached header/schema read from before the rewrite — the assertion cares about what's
        // durably on disk, which a new connection always re-reads.
        $fresh = new PDO('sqlite:' . $db);
        self::assertSame(2, (int) $fresh->query('PRAGMA auto_vacuum')->fetchColumn(), 'retainBytes() converts the legacy db to incremental auto_vacuum');
        self::assertLessThanOrEqual($cap, $rc->sizeBytes(), 'size reclaim works once converted');
    }
}
