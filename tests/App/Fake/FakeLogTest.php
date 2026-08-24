<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Fake;

use Funnypot\App\Render\Fake\FakeLog;
use Funnypot\App\Render\Fake\FrozenClock;
use PHPUnit\Framework\TestCase;

final class FakeLogTest extends TestCase
{
    /**
     * Every dotted-quad that is an actual source-IP FIELD must sit in RFC1918 / TEST-NET (critique S1):
     * these fabricated lines are display-only and must never file AbuseIPDB reports against real hosts.
     * UA/referer version strings (e.g. Chrome/125.0.0.0) also look like quads, so quoted fields are
     * stripped before scanning — what remains are the intended IP fields only.
     */
    private static function assertAllIpsPrivate(array $lines): void
    {
        foreach ($lines as $line) {
            $stripped = preg_replace('/"[^"]*"/', '', $line);
            if (preg_match_all('/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/', $stripped, $m, PREG_SET_ORDER)) {
                foreach ($m as $q) {
                    $a = (int) $q[1];
                    $b = (int) $q[2];
                    self::assertTrue(
                        self::isPrivateOrDoc($a, $b),
                        "IP {$q[0]} is not RFC1918/TEST-NET in line: {$line}"
                    );
                }
            }
        }
    }

    private static function isPrivateOrDoc(int $a, int $b): bool
    {
        if ($a === 10) {
            return true;
        }
        if ($a === 172 && $b >= 16 && $b <= 31) {
            return true;
        }
        if ($a === 192 && $b === 168) {
            return true;
        }
        if ($a === 192 && $b === 0) {   // 192.0.2.0/24 TEST-NET-1
            return true;
        }
        if ($a === 198 && $b === 51) {  // 198.51.100.0/24 TEST-NET-2
            return true;
        }
        if ($a === 203 && $b === 0) {   // 203.0.113.0/24 TEST-NET-3
            return true;
        }
        return false;
    }

    public function test_auth_log_is_deterministic_for_same_seed(): void
    {
        $a = FakeLog::fromSeed(4242)->authLog(500);
        $b = FakeLog::fromSeed(4242)->authLog(500);
        self::assertSame($a, $b);
        self::assertCount(500, $a);
    }

    public function test_access_log_is_deterministic_for_same_seed(): void
    {
        $a = FakeLog::fromSeed(4242)->accessLog(500);
        $b = FakeLog::fromSeed(4242)->accessLog(500);
        self::assertSame($a, $b);
        self::assertCount(500, $a);
    }

    public function test_different_seeds_diverge(): void
    {
        self::assertNotSame(
            FakeLog::fromSeed(1)->authLog(200),
            FakeLog::fromSeed(2)->authLog(200)
        );
        self::assertNotSame(
            FakeLog::fromSeed(1)->accessLog(200),
            FakeLog::fromSeed(2)->accessLog(200)
        );
    }

    public function test_every_auth_log_ip_is_private_or_doc_across_seeds(): void
    {
        for ($seed = 1; $seed <= 12; $seed++) {
            self::assertAllIpsPrivate(FakeLog::fromSeed($seed)->authLog(1200));
        }
    }

    public function test_every_access_log_ip_is_private_or_doc_across_seeds(): void
    {
        for ($seed = 1; $seed <= 12; $seed++) {
            self::assertAllIpsPrivate(FakeLog::fromSeed($seed)->accessLog(1200));
        }
    }

    public function test_auth_log_lines_match_sshd_syslog_shape(): void
    {
        foreach (FakeLog::fromSeed(7)->authLog(300) as $line) {
            self::assertMatchesRegularExpression(
                '/^[A-Z][a-z]{2} [ 0-9]\d \d{2}:\d{2}:\d{2} \S+ sshd\[\d+\]: /',
                $line
            );
        }
    }

    public function test_access_log_lines_match_combined_shape(): void
    {
        foreach (FakeLog::fromSeed(7)->accessLog(300) as $line) {
            self::assertMatchesRegularExpression(
                '#^\d{1,3}(\.\d{1,3}){3} - - \[\d{2}/[A-Z][a-z]{2}/2026:\d{2}:\d{2}:\d{2} \+0000\] "(GET|POST|HEAD) \S+ HTTP/1\.1" \d{3} (\d+|-) "[^"]*" "[^"]*"$#',
                $line
            );
        }
    }

    public function test_publickey_bait_is_buried_with_inert_fingerprint(): void
    {
        $lines = FakeLog::fromSeed(99)->authLog(2000);
        $baits = array_values(array_filter($lines, static function (string $l): bool {
            return strpos($l, 'Accepted publickey for deploy') !== false;
        }));
        self::assertNotEmpty($baits, 'expected at least one buried publickey bait');
        foreach ($baits as $l) {
            // 43-char unpadded base64url fingerprint after "SHA256:".
            self::assertMatchesRegularExpression('#SHA256:[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])#', $l);
        }
    }

    /** @return list<string> the 12 Jan-Dec syslog month abbreviations, matching FakeLog's own list. */
    private static function months(): array
    {
        return ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    }

    public function test_auth_log_newest_line_is_anchored_to_frozen_now(): void
    {
        // The offsets are built so the LAST line lands exactly on FrozenClock::EPOCH — a live "now"
        // tail, not a span anchored to an unrelated random offset.
        $expected = sprintf('%s %2d %s', self::months()[FrozenClock::MONTH - 1], FrozenClock::DAY, FrozenClock::clock(FrozenClock::EPOCH));
        foreach ([1, 2, 4242, 987654321] as $seed) {
            $lines = FakeLog::fromSeed($seed)->authLog(500);
            self::assertStringStartsWith($expected, end($lines), "seed {$seed}: newest auth.log line must be frozen \"now\"");
        }
    }

    public function test_access_log_newest_line_is_anchored_to_frozen_now(): void
    {
        $expected = sprintf('[%02d/%s/%04d:%s +0000]', FrozenClock::DAY, self::months()[FrozenClock::MONTH - 1], FrozenClock::YEAR, FrozenClock::clock(FrozenClock::EPOCH));
        foreach ([1, 2, 4242, 987654321] as $seed) {
            $lines = FakeLog::fromSeed($seed)->accessLog(200);
            self::assertStringContainsString($expected, end($lines), "seed {$seed}: newest access.log line must be frozen \"now\"");
        }
    }

    public function test_root_dominates_failed_attempts(): void
    {
        $lines = FakeLog::fromSeed(3)->authLog(3000);
        $failed = 0;
        $rootFailed = 0;
        foreach ($lines as $l) {
            if (strpos($l, 'Failed password for ') === false) {
                continue;
            }
            $failed++;
            if (preg_match('/Failed password for (invalid user )?root /', $l)) {
                $rootFailed++;
            }
        }
        self::assertGreaterThan(0, $failed);
        // root ~35% target; assert it is clearly the single most common account.
        self::assertGreaterThan(0.20, $rootFailed / $failed);
    }
}
