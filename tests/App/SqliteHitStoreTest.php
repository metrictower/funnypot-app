<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\Storage\SqliteHitStore;
use PHPUnit\Framework\TestCase;

/**
 * The SQLite-canonical hit store: append shapes rows for the live feed, aggregates stay correct,
 * paging + retention behave, and an existing export log seeds an empty DB on first boot.
 */
final class SqliteHitStoreTest extends TestCase
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
        $p = sys_get_temp_dir() . '/fp_hits_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    /** @return array<string,mixed> */
    private function httpHit(string $ip, string $cc, bool $matched, string $body, string $tmpl): array
    {
        return [
            'ts' => '2026-08-18T10:00:00+00:00',
            'ip' => $ip,
            'method' => 'GET',
            'path' => '/.git/config',
            'matched' => $matched,
            'severity' => 'medium',
            'served' => $matched,
            'templates' => $tmpl !== '' ? [$tmpl] : [],
            'body' => $body,
            'geo' => ['cc' => $cc, 'lat' => 1.0, 'lon' => 2.0],
        ];
    }

    public function test_append_delta_stats_widgets(): void
    {
        $store = new SqliteHitStore($this->dbPath());
        $store->append($this->httpHit('1.1.1.1', 'US', true, '', 'git-config'));
        $store->append($this->httpHit('2.2.2.2', 'DE', true, 'cmd=whoami', 'struts'));
        $store->append([
            'ts' => '2026-08-18T10:05:00+00:00', 'ip' => '3.3.3.3', 'method' => 'SSH',
            'event' => 'command', 'path' => 'uname -a', 'body' => 'uname -a',
            'matched' => false, 'served' => false, 'geo' => ['cc' => 'CN'],
        ]);

        $delta = $store->delta(0);
        self::assertTrue($delta['reset']);
        self::assertSame(3, $delta['cursor']);
        self::assertCount(3, $delta['rows']);
        self::assertSame('1.1.1.1', $delta['rows'][0]['ip']);  // oldest-first
        self::assertSame('SSH', $delta['rows'][2]['method']);
        self::assertSame('uname -a', $delta['rows'][2]['body']);

        $stats = $store->stats();
        self::assertSame(3, $stats['total']);
        self::assertSame(2, $stats['detections']);
        self::assertSame(2, $stats['served']);
        self::assertSame(3, $stats['ips']);
        self::assertSame(2, $stats['harvested']);          // the two non-empty bodies

        $w = $store->widgets();
        self::assertCount(3, $w['talkers']);
        self::assertCount(3, $w['countries']);
        self::assertEqualsCanonicalizing(['git-config', 'struts'], array_column($w['templates'], 't'));
    }

    public function test_delta_since_cursor_returns_only_new_rows(): void
    {
        $store = new SqliteHitStore($this->dbPath());
        $store->append($this->httpHit('1.1.1.1', 'US', true, '', 'a'));
        $store->append($this->httpHit('2.2.2.2', 'US', true, '', 'b'));

        $since = $store->delta(1);
        self::assertFalse($since['reset']);
        self::assertSame(2, $since['cursor']);
        self::assertCount(1, $since['rows']);
        self::assertSame('2.2.2.2', $since['rows'][0]['ip']);
    }

    public function test_older_pages_newest_first(): void
    {
        $store = new SqliteHitStore($this->dbPath());
        for ($i = 0; $i < 3; $i++) {
            $store->append($this->httpHit("9.0.0.$i", 'US', false, '', ''));
        }
        $older = $store->older(0);
        self::assertFalse($older['more']);
        self::assertSame('9.0.0.2', $older['rows'][0]['ip']);   // newest first
        self::assertSame('9.0.0.0', $older['rows'][2]['ip']);
    }

    public function test_prune_keeps_newest(): void
    {
        $store = new SqliteHitStore($this->dbPath());
        for ($i = 0; $i < 5; $i++) {
            $store->append($this->httpHit("5.0.0.$i", 'US', false, '', ''));
        }
        $store->prune(2);
        self::assertSame(2, $store->stats()['total']);
        $rows = $store->delta(0)['rows'];
        self::assertSame('5.0.0.3', $rows[0]['ip']);            // oldest surviving
        self::assertSame('5.0.0.4', $rows[1]['ip']);
    }

    public function test_clear_empties_the_store(): void
    {
        $store = new SqliteHitStore($this->dbPath());
        $store->append($this->httpHit('1.1.1.1', 'US', true, '', 'x'));
        $store->clear();
        self::assertSame(0, $store->stats()['total']);
    }

    public function test_import_on_empty_migrates_from_export_log(): void
    {
        $log = sys_get_temp_dir() . '/fp_log_' . bin2hex(random_bytes(6)) . '.log';
        $this->tmp[] = $log;
        $rows = [
            $this->httpHit('7.7.7.7', 'FR', true, '', 'git-config'),
            $this->httpHit('8.8.8.8', 'FR', false, '', ''),
        ];
        $lines = '';
        foreach ($rows as $r) {
            $lines .= json_encode($r, JSON_UNESCAPED_SLASHES) . "\n";
        }
        file_put_contents($log, $lines);

        // Empty DB + an existing export log => the constructor seeds the DB once.
        $store = new SqliteHitStore($this->dbPath(), $log);
        self::assertSame(2, $store->stats()['total']);
        self::assertSame('7.7.7.7', $store->delta(0)['rows'][0]['ip']);
    }

    public function test_retain_days_drops_old_rows(): void
    {
        $store = new SqliteHitStore($this->dbPath());
        // two ancient rows + two fresh
        foreach (['1.1.1.1', '2.2.2.2'] as $ip) {
            $store->append(['ts' => '2020-01-01T00:00:00+00:00', 'ip' => $ip, 'method' => 'GET', 'path' => '/old']);
        }
        foreach (['3.3.3.3', '4.4.4.4'] as $ip) {
            $store->append(['ts' => gmdate('c'), 'ip' => $ip, 'method' => 'GET', 'path' => '/new']);
        }

        self::assertSame(2, $store->retainDays(30));       // the two 2020 rows
        self::assertSame(2, $store->stats()['total']);
        foreach ($store->delta(0)['rows'] as $r) {
            self::assertSame('/new', $r['path']);
        }
        self::assertSame(0, $store->retainDays(30));       // idempotent
    }

    public function test_retain_bytes_caps_disk(): void
    {
        $store = new SqliteHitStore($this->dbPath());
        for ($i = 0; $i < 6000; $i++) {
            $store->append(['ts' => '2026-08-18T10:00:00+00:00', 'ip' => '9.9.9.' . ($i % 250), 'method' => 'GET',
                'path' => '/x', 'body' => str_repeat('A', 200)]);
        }
        // Checkpoint first so $before (and the cap derived from it) reflects what retainBytes()'s OWN
        // leading checkpoint will already see — otherwise a wal accumulated by the appends above would
        // inflate $before, and retainBytes()'s checkpoint alone could satisfy a cap derived from that
        // inflated figure without deleting a single row (FP-0249: sizeBytes() is now wal-inclusive).
        $store->checkpointWal();
        $before = $store->sizeBytes();
        $cap = (int) ($before * 0.7);

        $removed = $store->retainBytes($cap);
        self::assertGreaterThan(0, $removed);
        self::assertLessThanOrEqual($cap, $store->sizeBytes());
        self::assertGreaterThan(0, $store->stats()['total']);   // trimmed, not drained
    }

    public function test_filters_narrow_the_feed(): void
    {
        $store = new SqliteHitStore($this->dbPath());
        $store->append($this->httpHit('1.1.1.1', 'US', true, '', 'git-config'));   // GET
        $store->append(['ts' => gmdate('c'), 'ip' => '2.2.2.2', 'method' => 'SSH', 'event' => 'command',
            'path' => 'uname -a', 'body' => 'uname -a']);
        $store->append(['ts' => gmdate('c'), 'ip' => '3.3.3.3', 'method' => 'SSH', 'event' => 'connect', 'path' => '']);

        // "all SSH commands"
        $rows = $store->delta(0, ['method' => 'SSH', 'event' => 'command'])['rows'];
        self::assertCount(1, $rows);
        self::assertSame('uname -a', $rows[0]['body']);

        // all SSH events
        self::assertCount(2, $store->delta(0, ['method' => 'SSH'])['rows']);

        // free-text over path/body
        self::assertCount(1, $store->delta(0, ['q' => 'uname'])['rows']);

        // matched-only
        $m = $store->delta(0, ['matched' => true])['rows'];
        self::assertCount(1, $m);
        self::assertSame('GET', $m[0]['method']);

        // older() honours filters too, and its cursor still tracks the newest row overall
        self::assertCount(2, $store->older(0, ['method' => 'SSH'])['rows']);
        self::assertSame(3, $store->delta(0, ['method' => 'SSH'])['cursor']);
    }

    public function test_known_attacker_flag_and_filter(): void
    {
        $store = new SqliteHitStore($this->dbPath());
        $store->append($this->httpHit('1.1.1.1', 'US', true, '', 'x'));      // not known
        $e = $this->httpHit('6.6.6.6', 'RU', true, '', 'y');
        $e['known_attacker'] = true;
        $store->append($e);

        $rows = $store->delta(0)['rows'];
        self::assertFalse($rows[0]['known_attacker']);
        self::assertTrue($rows[1]['known_attacker']);

        $known = $store->delta(0, ['known' => true])['rows'];
        self::assertCount(1, $known);
        self::assertSame('6.6.6.6', $known[0]['ip']);
    }

    public function test_probe_velocity(): void
    {
        $store = new SqliteHitStore($this->dbPath());
        foreach (['/a', '/b', '/c', '/a'] as $p) {   // 3 distinct recent paths (/a repeated)
            $store->append(['ts' => gmdate('c'), 'ip' => '9.9.9.9', 'method' => 'GET', 'path' => $p]);
        }
        $store->append(['ts' => gmdate('c', time() - 3600), 'ip' => '9.9.9.9', 'method' => 'GET', 'path' => '/old']);
        $store->append(['ts' => gmdate('c'), 'ip' => '1.1.1.1', 'method' => 'GET', 'path' => '/x']);   // other IP

        $v = $store->probeVelocity('9.9.9.9');
        self::assertSame(3, $v['recent']);       // distinct /a /b /c in the last 60s
        self::assertSame(3, $v['extended']);     // the 1h-old /old is outside the 10min window
        self::assertSame(['recent' => 0, 'extended' => 0], $store->probeVelocity('unknown'));
    }

    public function test_recent_event_count(): void
    {
        $store = new SqliteHitStore($this->dbPath());
        foreach (range(1, 3) as $i) {   // 3 recent ai-api hits from the target IP
            $store->append(['ts' => gmdate('c'), 'ip' => '9.9.9.9', 'method' => 'POST', 'path' => '/v1/chat/completions', 'event' => 'ai-api']);
        }
        $store->append(['ts' => gmdate('c', time() - 700), 'ip' => '9.9.9.9', 'method' => 'POST', 'path' => '/v1/chat/completions', 'event' => 'ai-api']);   // outside 600s
        $store->append(['ts' => gmdate('c'), 'ip' => '9.9.9.9', 'method' => 'GET', 'path' => '/', 'event' => 'llm-fake']);                                    // different event
        $store->append(['ts' => gmdate('c'), 'ip' => '1.1.1.1', 'method' => 'POST', 'path' => '/v1/chat/completions', 'event' => 'ai-api']);                  // different IP

        self::assertSame(3, $store->recentEventCount('9.9.9.9', 'ai-api', 600));      // window excludes the old one
        self::assertSame(4, $store->recentEventCount('9.9.9.9', 'ai-api', 86400));    // wider window includes it
        self::assertSame(1, $store->recentEventCount('9.9.9.9', 'llm-fake', 600));    // events counted separately
        self::assertSame(1, $store->recentEventCount('1.1.1.1', 'ai-api', 600));      // IPs counted separately
        self::assertSame(0, $store->recentEventCount('unknown', 'ai-api', 600));
    }

    public function test_binary_bytes_are_sanitised_not_dropped(): void
    {
        $store = new SqliteHitStore($this->dbPath());
        $store->append([
            'ts' => '2026-08-18T10:00:00+00:00', 'ip' => '4.4.4.4', 'method' => 'MYSQL',
            'event' => 'connect', 'path' => "\x00\xff\x10raw", 'body' => "\x00binary",
            'matched' => false, 'served' => false,
        ]);
        $row = $store->delta(0)['rows'][0];
        self::assertStringContainsString('\\x00', $row['path']);
        self::assertStringContainsString('raw', $row['path']);
        self::assertSame('\\x00binary', $row['body']);
    }

    public function test_recording_persistence_and_filtering(): void
    {
        $store = new SqliteHitStore($this->dbPath());
        $store->append([
            'ts' => '2026-08-29T12:00:00+00:00',
            'ip' => '5.5.5.5',
            'method' => 'SIP',
            'event' => 'call_end',
            'path' => 'SIP call ended: 101',
            'recording' => '/funnypot/recording?id=call-test-123',
        ]);
        $store->append([
            'ts' => '2026-08-29T12:01:00+00:00',
            'ip' => '5.5.5.5',
            'method' => 'SIP',
            'event' => 'login',
            'path' => 'SIP REGISTER ext:101',
            'recording' => '',
        ]);

        $rows = $store->delta(0)['rows'];
        self::assertCount(2, $rows);
        self::assertSame('/funnypot/recording?id=call-test-123', $rows[0]['recording']);
        self::assertSame('', $rows[1]['recording']);

        // Filter by recording: 1
        $recs = $store->delta(0, ['recording' => '1'])['rows'];
        self::assertCount(1, $recs);
        self::assertSame('call_end', $recs[0]['event']);

        // Filter by method: SIP (all SIP logs)
        $sip = $store->delta(0, ['method' => 'SIP'])['rows'];
        self::assertCount(2, $sip);
    }

    public function testUserAgentAndToolAttribution(): void
    {
        $store = new SqliteHitStore($this->dbPath());

        $store->append([
            'ts' => '2026-08-30T10:00:00+00:00',
            'ip' => '172.20.10.3',
            'method' => 'SIP',
            'event' => 'call',
            'path' => 'SIP call connected: 100',
            'ua' => 'Zoiper v2.10.20.4_1',
            'tool' => 'zoiper-softphone',
        ]);
        $store->append([
            'ts' => '2026-08-30T10:01:00+00:00',
            'ip' => '1.2.3.4',
            'method' => 'GET',
            'event' => 'scan',
            'path' => '/login',
            'ua' => 'sqlmap/1.7.8#stable',
            'tool' => 'sqlmap',
        ]);
        $store->append([
            'ts' => '2026-08-30T10:02:00+00:00',
            'ip' => '5.6.7.8',
            'method' => 'RTSP',
            'event' => 'probe',
            'path' => 'rtsp://test/live',
            'userAgent' => 'Lavf/58.29.100',
        ]);

        $rows = $store->delta(0)['rows'];
        self::assertCount(3, $rows);
        self::assertSame('Zoiper v2.10.20.4_1', $rows[0]['ua']);
        self::assertSame('zoiper-softphone', $rows[0]['tool']);

        self::assertSame('sqlmap/1.7.8#stable', $rows[1]['ua']);
        self::assertSame('sqlmap', $rows[1]['tool']);

        self::assertSame('Lavf/58.29.100', $rows[2]['ua']);
        self::assertSame('', $rows[2]['tool']);

        // Filter exact match by tool
        $filtered = $store->delta(0, ['tool' => 'zoiper-softphone'])['rows'];
        self::assertCount(1, $filtered);
        self::assertSame('172.20.10.3', $filtered[0]['ip']);

        // Free-text search by q matching tool or ua
        $qSearch = $store->delta(0, ['q' => 'sqlmap'])['rows'];
        self::assertCount(1, $qSearch);
        self::assertSame('1.2.3.4', $qSearch[0]['ip']);
    }
}


