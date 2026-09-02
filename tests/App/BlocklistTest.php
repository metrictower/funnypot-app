<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\ThreatIntel\Blocklist;
use PHPUnit\Framework\TestCase;

/**
 * The threat-intel blocklist: parse feeds, corroborate across them, and answer isKnown() fast.
 * An injected fetcher stands in for the network so the tests are hermetic.
 */
final class BlocklistTest extends TestCase
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
        $p = sys_get_temp_dir() . '/fp_intel_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    public function test_import_parses_skips_and_corroborates(): void
    {
        $feeds = [
            'feedA' => "# a comment\n1.2.3.4\n5.6.7.8\n10.0.0.0/8\nnot-an-ip\n",  // CIDR + junk skipped
            'feedB' => "1.2.3.4\n9.9.9.9\n",                                       // 1.2.3.4 seen twice
            'ipsum' => "8.8.8.8\t7\n; ipsum header\n",                             // trailing count column
        ];
        $bl = new Blocklist($this->dbPath(), 1);
        $r = $bl->import(static fn (string $u): ?string => $feeds[$u] ?? null, array_keys($feeds));

        self::assertSame(3, $r['sources']);
        self::assertSame(4, $r['ips']);              // 1.2.3.4, 5.6.7.8, 9.9.9.9, 8.8.8.8
        self::assertSame(1, $r['ranges']);           // 10.0.0.0/8
        self::assertTrue($bl->isKnown('1.2.3.4'));
        self::assertTrue($bl->isKnown('8.8.8.8'));
        self::assertTrue($bl->isKnown('10.5.5.5'));   // inside the 10.0.0.0/8 range
        self::assertFalse($bl->isKnown('11.0.0.1'));  // outside it
        self::assertFalse($bl->isKnown('192.168.1.1'));
        self::assertFalse($bl->isKnown('unknown'));
        self::assertFalse($bl->isKnown(''));
    }

    public function test_cidr_ranges_and_boundaries(): void
    {
        $bl = new Blocklist($this->dbPath(), 1);
        $r = $bl->import(static fn (string $u): ?string => "203.0.113.0/24\n198.51.100.128/25\n", ['nets']);

        self::assertSame(0, $r['ips']);
        self::assertSame(2, $r['ranges']);
        self::assertTrue($bl->isKnown('203.0.113.0'));     // network address
        self::assertTrue($bl->isKnown('203.0.113.255'));   // broadcast
        self::assertFalse($bl->isKnown('203.0.114.0'));    // just outside
        self::assertTrue($bl->isKnown('198.51.100.200'));  // inside the /25 upper half
        self::assertFalse($bl->isKnown('198.51.100.10'));  // lower half, outside the /25
    }

    public function test_ipv6_cidr_is_skipped(): void
    {
        $bl = new Blocklist($this->dbPath(), 1);
        $r = $bl->import(static fn (string $u): ?string => "2001:db8::/32\n5.5.5.5\n", ['x']);

        self::assertSame(1, $r['ips']);
        self::assertSame(0, $r['ranges']);                 // IPv6 CIDR not stored
        self::assertFalse($bl->isKnown('2001:db8::1'));
        self::assertTrue($bl->isKnown('5.5.5.5'));
    }

    public function test_ranges_ignore_the_corroboration_threshold(): void
    {
        // minLists=2 gates exact IPs, but a curated CIDR range still flags on its own.
        $bl = new Blocklist($this->dbPath(), 2);
        $bl->import(static fn (string $u): ?string => "9.9.9.9\n203.0.113.0/24\n", ['one']);

        self::assertFalse($bl->isKnown('9.9.9.9'));        // exact, only 1 feed < minLists 2
        self::assertTrue($bl->isKnown('203.0.113.50'));    // range still flags
    }

    public function test_min_lists_corroboration(): void
    {
        $feeds = ['a' => "1.1.1.1\n2.2.2.2\n", 'b' => "1.1.1.1\n"]; // 1.1.1.1 in 2 feeds, 2.2.2.2 in 1
        $bl = new Blocklist($this->dbPath(), 2);                    // require >= 2 feeds to flag
        $bl->import(static fn (string $u): ?string => $feeds[$u] ?? null, array_keys($feeds));

        self::assertTrue($bl->isKnown('1.1.1.1'));
        self::assertFalse($bl->isKnown('2.2.2.2'));
    }

    public function test_ipv6_and_reimport_replaces(): void
    {
        $bl = new Blocklist($this->dbPath(), 1);
        $bl->import(static fn (string $u): ?string => "2001:db8::1\n", ['x']);
        self::assertTrue($bl->isKnown('2001:db8::1'));
        self::assertSame(1, $bl->count());

        $bl->import(static fn (string $u): ?string => "3.3.3.3\n", ['y']);
        self::assertFalse($bl->isKnown('2001:db8::1'));   // old set replaced
        self::assertTrue($bl->isKnown('3.3.3.3'));
    }

    public function test_missing_db_fails_open(): void
    {
        // A brand new instance whose feeds all failed to fetch never flags and never throws.
        $bl = new Blocklist($this->dbPath(), 1);
        self::assertFalse($bl->isKnown('1.2.3.4'));
        self::assertSame(0, $bl->count());
    }

    public function test_total_feed_outage_keeps_existing_data(): void
    {
        // FP-0247 (Fix B): every feed fails to fetch on the next refresh — the prior intel must survive.
        $db = $this->dbPath();
        $bl = new Blocklist($db, 1);
        $bl->import(static fn (string $u): ?string => "1.2.3.4\n203.0.113.0/24\n", ['ok']);
        self::assertTrue($bl->isKnown('1.2.3.4'));
        self::assertSame(1, $bl->count());

        $r = $bl->import(static fn (string $u): ?string => null, ['a', 'b', 'c']);   // total outage
        self::assertTrue($r['skipped']);
        self::assertSame(0, $r['sources']);
        self::assertTrue($bl->isKnown('1.2.3.4'), 'existing exact IP must survive an outage');
        self::assertTrue($bl->isKnown('203.0.113.50'), 'existing range must survive an outage');
        self::assertSame(1, $bl->count());
    }

    public function test_zero_parsed_tokens_keeps_existing_data(): void
    {
        // Feeds reachable but returning comment-only / garbage bodies (error HTML) parse to zero valid
        // tokens — that must NOT replace corroborated data with an empty table.
        $db = $this->dbPath();
        $bl = new Blocklist($db, 1);
        $bl->import(static fn (string $u): ?string => "9.9.9.9\n", ['ok']);
        self::assertTrue($bl->isKnown('9.9.9.9'));

        $garbage = "# just a comment\n; another\n<html><body>502 Bad Gateway</body></html>\n";
        $r = $bl->import(static fn (string $u): ?string => $garbage, ['x', 'y']);
        self::assertTrue($r['skipped']);
        self::assertSame(2, $r['sources']);         // fetched, but nothing parseable
        self::assertTrue($bl->isKnown('9.9.9.9'), 'existing data must survive a zero-token refresh');
    }

    public function test_refreshed_at_set_only_on_successful_import(): void
    {
        $db = $this->dbPath();
        $bl = new Blocklist($db, 1);
        self::assertNull($bl->refreshedAt());               // never refreshed

        $bl->import(static fn (string $u): ?string => "1.2.3.4\n", ['ok']);
        $stamp = $bl->refreshedAt();
        self::assertNotNull($stamp);
        self::assertFalse($bl->isStale());                  // just refreshed

        // A subsequent total outage must NOT advance the refresh stamp.
        $bl->import(static fn (string $u): ?string => null, ['down']);
        self::assertSame($stamp, $bl->refreshedAt());
    }

    public function test_stale_when_never_refreshed(): void
    {
        // Fail-safe: an instance that has never had a successful import reads as stale.
        $bl = new Blocklist($this->dbPath(), 1);
        self::assertTrue($bl->isStale());
        self::assertTrue($bl->isStale(48));
    }
}
