<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\ThreatIntel\ThreatIntelReporter;
use PHPUnit\Framework\TestCase;

/**
 * Threat Intel reporting to our own funnypot-mainnet service: enqueue (guarded, local) then drain
 * (the HTTP POSTs). Mirrors the AbuseIpdb suite — the overriding property is the self-exclude
 * invariant and the one-report-per-IP-per-window throttle — plus the reporter's own concerns:
 * the injected base URL + /v1/report endpoint, the `Key:` header, the persisted sensor_id, forwarded
 * signals, and fail-silent behaviour when the transport errors or times out.
 */
final class ThreatIntelReporterTest extends TestCase
{
    private const URL = 'https://threatintel.example';

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
            foreach (['', '-wal', '-shm'] as $s) {
                @unlink($f . $s);
            }
        }
        $this->tmp = [];
    }

    private function dbPath(): string
    {
        $p = sys_get_temp_dir() . '/fp_ti_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    /**
     * A recording sender proving what would actually have gone out.
     * @param list<array{url:string,headers:array<string>,fields:array<string,mixed>}> $calls
     */
    private function recorder(array &$calls, int $status = 200): callable
    {
        return static function (string $url, array $headers, string $body) use (&$calls, $status): array {
            parse_str($body, $fields);
            $calls[] = ['url' => $url, 'headers' => $headers, 'fields' => $fields];

            return ['status' => $status, 'body' => '{}'];
        };
    }

    private function make(string $db, array $selfIps, int $cap = 1000, int $dedupH = 24, ?callable $sender = null, int $maxAgeH = 24): ThreatIntelReporter
    {
        return new ThreatIntelReporter(self::URL, 'KEY', $db, $selfIps, $cap, $dedupH, $sender, maxQueueAgeHours: $maxAgeH);
    }

    /** Rewrite a queued row's created_at to $iso, for the observation-timestamp / purge tests. */
    private function backdate(string $db, string $ip, string $iso): void
    {
        $pdo = new \PDO('sqlite:' . $db);
        $st = $pdo->prepare('UPDATE ti_queue SET created_at = :t WHERE ip = :ip');
        $st->execute([':t' => $iso, ':ip' => $ip]);
    }

    public function test_enqueue_then_drain_posts_to_v1_report_with_key_and_sensor_id(): void
    {
        $calls = [];
        $a = $this->make($this->dbPath(), ['203.0.113.9'], 1000, 24, $this->recorder($calls));

        self::assertTrue($a->enqueue('45.9.148.1', 'funnypot web honeypot, port 8080: GET http://x/.git/config', '21')['queued']);
        self::assertSame(1, $a->queueCount());
        self::assertCount(0, $calls);                       // nothing sent until drain

        $r = $a->drain();
        self::assertSame(1, $r['sent']);
        self::assertSame(0, $a->queueCount());

        self::assertSame(self::URL . '/v1/report', $calls[0]['url']);   // base URL + appended path
        self::assertContains('Key: KEY', $calls[0]['headers']);
        self::assertSame('45.9.148.1', $calls[0]['fields']['ip']);
        self::assertSame('21', $calls[0]['fields']['categories']);
        self::assertArrayHasKey('timestamp', $calls[0]['fields']);
        self::assertNotSame('', (string) ($calls[0]['fields']['sensor_id'] ?? ''));   // persisted per-install id
        self::assertArrayNotHasKey('signals', $calls[0]['fields']);     // additive: absent by default
    }

    public function test_base_url_with_trailing_slash_is_normalised(): void
    {
        $calls = [];
        $a = new ThreatIntelReporter(self::URL . '/', 'KEY', $this->dbPath(), ['203.0.113.9'], 1000, 24, $this->recorder($calls));
        $a->enqueue('45.9.148.1', 'x');
        $a->drain();
        self::assertSame(self::URL . '/v1/report', $calls[0]['url']);
    }

    public function test_noop_without_key(): void
    {
        $a = new ThreatIntelReporter(self::URL, '', $this->dbPath(), ['203.0.113.9']);
        self::assertSame('no api key', $a->enqueue('45.9.148.1', 'x')['reason']);
        self::assertSame(0, $a->queueCount());
    }

    public function test_never_enqueues_self(): void
    {
        $a = $this->make($this->dbPath(), ['45.9.148.1']);
        self::assertSame('self', $a->enqueue('45.9.148.1', 'x')['reason']);
        self::assertSame(0, $a->queueCount());
    }

    public function test_inert_without_self_ips(): void
    {
        $a = $this->make($this->dbPath(), []);
        self::assertSame('self ips not configured', $a->enqueue('45.9.148.1', 'x')['reason']);
        self::assertSame(0, $a->queueCount());
    }

    public function test_skips_private_and_invalid(): void
    {
        $a = $this->make($this->dbPath(), ['203.0.113.9']);
        foreach (['192.168.1.5', '10.0.0.1', '127.0.0.1', 'not-an-ip'] as $ip) {
            self::assertFalse($a->enqueue($ip, 'x')['queued']);
        }
        self::assertSame(0, $a->queueCount());
    }

    public function test_dedup_one_report_per_window(): void
    {
        $calls = [];
        $a = $this->make($this->dbPath(), ['203.0.113.9'], 1000, 24, $this->recorder($calls));

        self::assertTrue($a->enqueue('45.9.148.1', 'hit 1')['queued']);
        self::assertSame('deduped', $a->enqueue('45.9.148.1', 'hit 2')['reason']);   // hundreds of hits -> one report
        self::assertSame('deduped', $a->enqueue('45.9.148.1', 'hit 3')['reason']);
        self::assertSame(1, $a->queueCount());
    }

    public function test_daily_cap_stops_the_drain(): void
    {
        $calls = [];
        $a = $this->make($this->dbPath(), ['203.0.113.9'], 2, 24, $this->recorder($calls));
        foreach (['45.9.148.1', '45.9.148.2', '45.9.148.3'] as $ip) {
            $a->enqueue($ip, 'x');
        }
        $r = $a->drain();
        self::assertSame(2, $r['sent']);
        self::assertSame(1, $r['pending']);   // 3rd left for tomorrow
        self::assertCount(2, $calls);
    }

    public function test_drain_drops_4xx_retries_5xx(): void
    {
        // 5xx: kept and retried up to 3 attempts, then dropped.
        $calls5 = [];
        $a = $this->make($this->dbPath(), ['203.0.113.9'], 1000, 24, $this->recorder($calls5, 500));
        $a->enqueue('45.9.148.1', 'x');
        $a->drain();
        self::assertSame(1, $a->queueCount());   // still queued after a 5xx
        $a->drain();
        $a->drain();
        self::assertSame(0, $a->queueCount());   // dropped after 3 attempts

        // 4xx: dropped immediately (it will never succeed).
        $calls4 = [];
        $b = $this->make($this->dbPath(), ['203.0.113.9'], 1000, 24, $this->recorder($calls4, 422));
        $b->enqueue('45.9.148.2', 'x');
        $b->drain();
        self::assertSame(0, $b->queueCount());
    }

    public function test_fail_silent_when_transport_throws(): void
    {
        // A total transport failure (thrown exception, e.g. a timeout) must never escape the drain,
        // and the row must survive for a later tick — never dropped as if it succeeded.
        $thrower = static function (): array {
            throw new \RuntimeException('connection timed out');
        };
        $a = $this->make($this->dbPath(), ['203.0.113.9'], 1000, 24, $thrower);
        $a->enqueue('45.9.148.1', 'x');

        $r = $a->drain();   // must not throw
        self::assertSame(0, $r['sent']);
        self::assertSame(1, $a->queueCount());   // kept for retry, like a 5xx
    }

    public function test_signals_forwarded_when_present(): void
    {
        $calls = [];
        $a = $this->make($this->dbPath(), ['203.0.113.9'], 1000, 24, $this->recorder($calls));
        $a->enqueue('45.9.148.1', 'x', 'bad_bot', ['missing_ua' => true, 'ua_class' => 'scanner'], 87.5);
        $a->drain();

        self::assertSame('bad_bot', $calls[0]['fields']['categories']);
        self::assertSame(['missing_ua' => '1', 'ua_class' => 'scanner'], $calls[0]['fields']['signals']);
        self::assertSame('87.5', (string) $calls[0]['fields']['confidence']);
    }

    public function test_sensor_id_is_stable_across_instances(): void
    {
        $db = $this->dbPath();
        $first = $this->make($db, ['203.0.113.9'])->sensorId();
        self::assertMatchesRegularExpression('/^[0-9a-f-]{36}$/', $first);
        self::assertSame($first, $this->make($db, ['203.0.113.9'])->sensorId());   // fresh instance, same store
    }

    public function test_tables_are_independent_of_abuseipdb(): void
    {
        // The reporter uses its own ti_* tables so the two destinations dedup/cap independently.
        $db = $this->dbPath();
        $this->make($db, ['203.0.113.9'])->enqueue('45.9.148.1', 'x');
        $pdo = new \PDO('sqlite:' . $db);
        $names = $pdo->query("SELECT name FROM sqlite_master WHERE type='table'")->fetchAll(\PDO::FETCH_COLUMN);
        self::assertContains('ti_queue', $names);
        self::assertNotContains('abuse_queue', $names);   // AbuseIpdb's tables are not touched
    }

    public function test_429_is_transient_row_survives_and_pass_stops(): void
    {
        $calls = [];
        $db = $this->dbPath();
        $a = $this->make($db, ['203.0.113.9'], 1000, 24, $this->recorder($calls, 429));
        $a->enqueue('45.9.148.1', 'x');
        $a->enqueue('45.9.148.2', 'y');
        $r = $a->drain();
        self::assertSame(0, $r['sent']);
        self::assertSame(0, $r['failed']);
        self::assertSame(2, $a->queueCount());
        self::assertCount(1, $calls);
    }

    public function test_drain_sends_observation_timestamp_not_drain_time(): void
    {
        $calls = [];
        $db = $this->dbPath();
        $recorder = static function (string $url, array $headers, string $body) use (&$calls): array {
            parse_str($body, $f);
            $calls[] = (string) ($f['timestamp'] ?? '');

            return ['status' => 200, 'body' => '{}'];
        };
        $a = $this->make($db, ['203.0.113.9'], 1000, 24, $recorder);
        $a->enqueue('45.9.148.1', 'x');
        $observed = gmdate('c', time() - 2 * 3600);
        $this->backdate($db, '45.9.148.1', $observed);
        $a->drain();
        self::assertSame($observed, $calls[0]);
    }

    public function test_drain_purges_rows_older_than_max_age(): void
    {
        $calls = [];
        $db = $this->dbPath();
        $a = $this->make($db, ['203.0.113.9'], 1000, 24, $this->recorder($calls), 24);
        $a->enqueue('45.9.148.1', 'x');
        $this->backdate($db, '45.9.148.1', gmdate('c', time() - 48 * 3600));
        $r = $a->drain();
        self::assertSame(0, $r['sent']);
        self::assertCount(0, $calls);
        self::assertSame(0, $a->queueCount());
    }

    public function test_benign_scanner_is_never_enqueued(): void
    {
        $a = $this->make($this->dbPath(), ['203.0.113.9']);
        $r = $a->enqueue('162.142.125.10', 'x');
        self::assertFalse($r['queued']);
        self::assertStringStartsWith('benign scanner:', $r['reason']);
        self::assertSame(0, $a->queueCount());
    }

    public function test_self_cidr_covers_whole_range(): void
    {
        // FP-0247 (Fix J): mirror of AbuseIpdb — a self CIDR protects a whole shared-NAT range.
        $a = $this->make($this->dbPath(), ['203.0.113.0/24']);
        self::assertSame('self', $a->enqueue('203.0.113.50', 'x')['reason']);
        self::assertSame(0, $a->queueCount());
        self::assertTrue($a->enqueue('45.9.148.1', 'x')['queued']);
    }

    public function test_cgnat_source_is_never_enqueued(): void
    {
        $a = $this->make($this->dbPath(), ['203.0.113.9']);
        foreach (['100.64.0.1', '100.127.255.254', '192.0.0.5', '198.18.0.1'] as $ip) {
            self::assertSame('not a public ip', $a->enqueue($ip, 'x')['reason'], $ip);
        }
        self::assertSame(0, $a->queueCount());
    }

    public function test_categories_for_protocol(): void
    {
        self::assertSame('18,22', ThreatIntelReporter::categoriesForProtocol('ssh'));
        self::assertSame('14,15', ThreatIntelReporter::categoriesForProtocol('redis'));
    }
}
