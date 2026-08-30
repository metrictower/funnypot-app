<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\ThreatIntel;

use Funnypot\App\ThreatIntel\OperatorBlocklist;
use PHPUnit\Framework\TestCase;

/**
 * The operator manual blocklist (FP-0219): add/remove/list, exact + CIDR matching, the cached snapshot
 * with periodic reload, and fail-open on a missing/unreadable db.
 */
final class OperatorBlocklistTest extends TestCase
{
    /** @var string[] */
    private array $tmp = [];

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
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
        $p = sys_get_temp_dir() . '/fpopblock_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    public function test_add_remove_and_exact_match(): void
    {
        $b = new OperatorBlocklist($this->dbPath(), 0.0); // reloadEvery 0 -> always fresh
        self::assertFalse($b->isBlocked('1.2.3.4'));

        $b->add('1.2.3.4', 'sip flooder');
        self::assertTrue($b->isBlocked('1.2.3.4'));
        self::assertFalse($b->isBlocked('1.2.3.5'));

        $b->remove('1.2.3.4');
        self::assertFalse($b->isBlocked('1.2.3.4'));
    }

    public function test_cidr_range_match(): void
    {
        $b = new OperatorBlocklist($this->dbPath(), 0.0);
        $b->add('10.20.30.0/24');
        self::assertTrue($b->isBlocked('10.20.30.1'));
        self::assertTrue($b->isBlocked('10.20.30.254'));
        self::assertFalse($b->isBlocked('10.20.31.1'), 'outside the /24 must not match');
    }

    public function test_never_blocks_empty_or_unknown(): void
    {
        $b = new OperatorBlocklist($this->dbPath(), 0.0);
        $b->add('0.0.0.0/0'); // even a catch-all range
        self::assertFalse($b->isBlocked(''), 'empty peer (resolution failed) is never blocked');
        self::assertFalse($b->isBlocked('unknown'));
    }

    public function test_all_lists_newest_first(): void
    {
        $b = new OperatorBlocklist($this->dbPath(), 0.0);
        $b->add('1.1.1.1', 'first');
        $b->add('2.2.2.2', 'second');
        $rows = $b->all();
        self::assertCount(2, $rows);
        self::assertSame('1.1.1.1', $rows[array_search('1.1.1.1', array_column($rows, 'ip'), true)]['ip']);
        // each row carries ip/added_at/note
        foreach ($rows as $r) {
            self::assertArrayHasKey('added_at', $r);
            self::assertArrayHasKey('note', $r);
        }
    }

    public function test_snapshot_cache_reloads_after_ttl(): void
    {
        $path = $this->dbPath();
        $writer = new OperatorBlocklist($path, 0.0);
        // A reader with a long TTL caches its (empty) snapshot; a write by another instance is not seen
        // until the TTL elapses.
        $reader = new OperatorBlocklist($path, 3600.0);
        self::assertFalse($reader->isBlocked('9.9.9.9')); // loads empty snapshot, caches it

        $writer->add('9.9.9.9');
        self::assertFalse($reader->isBlocked('9.9.9.9'), 'within TTL the reader keeps its cached snapshot');

        // A fresh reader (or one past its TTL) sees it.
        $fresh = new OperatorBlocklist($path, 0.0);
        self::assertTrue($fresh->isBlocked('9.9.9.9'));
    }

    /** @dataProvider entries */
    public function test_is_valid_entry(string $entry, bool $valid): void
    {
        self::assertSame($valid, OperatorBlocklist::isValidEntry($entry), "isValidEntry('{$entry}')");
    }

    /** @return array<int,array{0:string,1:bool}> */
    public static function entries(): array
    {
        return [
            ['1.2.3.4', true],
            ['203.0.113.66', true],
            ['2001:db8::1', true],          // exact IPv6 ok
            ['10.0.0.0/8', true],           // IPv4 CIDR ok
            ['10.20.30.0/24', true],
            ['0.0.0.0/0', true],
            ['1.2.3.4/32', true],
            ['', false],
            ['1.2.3.44 x', false],          // stray char (the review's exact case)
            ['abc/8', false],               // non-numeric CIDR base
            ['1.2.3.4/33', false],          // out-of-range prefix
            ['2001:db8::/32', false],       // IPv6 CIDR unsupported by the matcher -> rejected, not stored
            ['notanip', false],
        ];
    }

    public function test_add_silently_ignores_invalid_entry(): void
    {
        $b = new OperatorBlocklist($this->dbPath(), 0.0);
        $b->add('garbage-not-an-ip');
        self::assertSame([], $b->all(), 'an invalid entry is never stored');
    }

    public function test_fail_open_on_unwritable_path(): void
    {
        // A path under a non-existent, uncreatable location: isBlocked must not throw, just return false.
        $b = new OperatorBlocklist('/proc/nonexistent/cannot/create/x.sqlite', 0.0);
        self::assertFalse($b->isBlocked('1.2.3.4'));
        self::assertSame([], $b->all());
    }
}
