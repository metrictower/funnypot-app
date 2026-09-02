<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\ThreatIntel\AbuseIpdb;
use PHPUnit\Framework\TestCase;

/**
 * AbuseIPDB reporting: enqueue (guarded, local) then drain (the HTTP POSTs). The overriding property
 * is the self-exclude invariant; the throttle is one report per IP per dedup window. A recording
 * sender proves what would actually have gone out.
 */
final class AbuseIpdbTest extends TestCase
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
            foreach (['', '-wal', '-shm'] as $s) {
                @unlink($f . $s);
            }
        }
        $this->tmp = [];
    }

    private function dbPath(): string
    {
        $p = sys_get_temp_dir() . '/fp_abuse_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    /** @param list<array{ip:string,cats:string}> $calls */
    private function recorder(array &$calls, int $status = 200): callable
    {
        return static function (string $url, array $headers, string $body) use (&$calls, $status): array {
            parse_str($body, $f);
            $calls[] = ['ip' => (string) ($f['ip'] ?? ''), 'cats' => (string) ($f['categories'] ?? '')];

            return ['status' => $status, 'body' => '{}'];
        };
    }

    private function make(string $db, array $selfIps, int $cap = 1000, int $dedupH = 24, ?callable $sender = null): AbuseIpdb
    {
        return new AbuseIpdb('KEY', $db, $selfIps, $cap, $dedupH, $sender);
    }

    public function test_enqueue_then_drain_sends_with_port_url_categories(): void
    {
        $calls = [];
        $a = $this->make($this->dbPath(), ['203.0.113.9'], 1000, 24, $this->recorder($calls));

        self::assertTrue($a->enqueue('45.9.148.1', 'funnypot web honeypot, port 8080: GET http://x/.git/config', '21')['queued']);
        self::assertSame(1, $a->queueCount());
        self::assertCount(0, $calls);                       // nothing sent until drain

        $r = $a->drain();
        self::assertSame(1, $r['sent']);
        self::assertSame(0, $a->queueCount());
        self::assertSame('45.9.148.1', $calls[0]['ip']);
        self::assertSame('21', $calls[0]['cats']);
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

    public function test_benign_scanner_is_never_enqueued(): void
    {
        // FP-0247 (Fix C): a documented research scanner (Censys) must never queue a report.
        $a = $this->make($this->dbPath(), ['203.0.113.9']);
        $r = $a->enqueue('162.142.125.10', 'x');
        self::assertFalse($r['queued']);
        self::assertStringStartsWith('benign scanner:', $r['reason']);
        self::assertSame(0, $a->queueCount());
    }

    public function test_self_cidr_covers_whole_range(): void
    {
        // FP-0247 (Fix J): a self entry may be a CIDR — every IP in our shared-NAT egress range is self.
        $a = $this->make($this->dbPath(), ['203.0.113.0/24']);
        self::assertSame('self', $a->enqueue('203.0.113.50', 'x')['reason']);
        self::assertSame('self', $a->enqueue('203.0.113.255', 'x')['reason']);
        self::assertSame(0, $a->queueCount());
        // An IP outside the self range is still reportable.
        self::assertTrue($a->enqueue('45.9.148.1', 'x')['queued']);
    }

    public function test_cgnat_source_is_never_enqueued(): void
    {
        // FP-0247 (Fix J): RFC 6598 CGNAT + benchmarking ranges are not publicly routable → never report.
        $a = $this->make($this->dbPath(), ['203.0.113.9']);
        foreach (['100.64.0.1', '100.127.255.254', '192.0.0.5', '198.18.0.1'] as $ip) {
            self::assertSame('not a public ip', $a->enqueue($ip, 'x')['reason'], $ip);
        }
        self::assertSame(0, $a->queueCount());
    }

    public function test_categories_for_protocol(): void
    {
        self::assertSame('18,22', AbuseIpdb::categoriesForProtocol('ssh'));
        self::assertSame('18,23', AbuseIpdb::categoriesForProtocol('telnet'));
        self::assertSame('18', AbuseIpdb::categoriesForProtocol('ftp'));
        self::assertSame('14,15', AbuseIpdb::categoriesForProtocol('redis'));
    }
}
