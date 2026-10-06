<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Storage;

use Funnypot\App\Storage\WriteCaptureStore;
use PHPUnit\Framework\TestCase;

/**
 * FP-0467 Phase 1: the bounded write-capture ledger. capture() records a source's written file;
 * verify() returns it back (the scanner's own sentinel) within the TTL. Per-source isolation, TTL
 * expiry, overwrite-on-recapture, content + per-scope caps, and fail-open on a broken store. Stores
 * only an opaque source scope — no raw IP.
 */
final class WriteCaptureStoreTest extends TestCase
{
    /** @var string[] */
    private array $tmp = [];
    private int $now = 1_000_000;

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
            @rmdir(\dirname($f));
        }
    }

    private function store(): WriteCaptureStore
    {
        $path = sys_get_temp_dir() . '/fp0467-' . bin2hex(random_bytes(6)) . '/write-capture.sqlite';
        $this->tmp[] = $path;

        return new WriteCaptureStore($path, function (): int { return $this->now; });
    }

    public function test_capture_then_verify_roundtrips_the_sentinel(): void
    {
        $s = $this->store();
        self::assertTrue($s->capture('src-a', '/var/www/html/out.txt', 'VULN_SENTINEL_9f3a', 'text/plain'));
        $hit = $s->verify('src-a', '/var/www/html/out.txt');
        self::assertNotNull($hit);
        self::assertSame('VULN_SENTINEL_9f3a', $hit['content']);
        self::assertSame('text/plain', $hit['content_type']);
    }

    public function test_verify_is_isolated_per_source(): void
    {
        $s = $this->store();
        $s->capture('src-a', '/var/www/html/out.txt', 'A', 'text/plain');
        self::assertNull($s->verify('src-b', '/var/www/html/out.txt'), 'a different source must not read the capture');
        self::assertNotNull($s->verify('src-a', '/var/www/html/out.txt'));
    }

    public function test_capture_expires_after_ttl(): void
    {
        $s = $this->store();
        $s->capture('src-a', '/p.txt', 'X', 'text/plain');
        self::assertNotNull($s->verify('src-a', '/p.txt'));
        $this->now += 1801; // > 30 min
        self::assertNull($s->verify('src-a', '/p.txt'), 'an expired capture must not verify');
    }

    public function test_recapture_overwrites_same_path(): void
    {
        $s = $this->store();
        $s->capture('src-a', '/p.txt', 'first', 'text/plain');
        $s->capture('src-a', '/p.txt', 'second', 'text/html');
        $hit = $s->verify('src-a', '/p.txt');
        self::assertNotNull($hit);
        self::assertSame('second', $hit['content']);
        self::assertSame('text/html', $hit['content_type']);
    }

    public function test_content_is_capped(): void
    {
        $s = $this->store();
        $big = str_repeat('A', 70000); // > 64 KB
        self::assertTrue($s->capture('src-a', '/big.txt', $big, 'text/plain'));
        $hit = $s->verify('src-a', '/big.txt');
        self::assertNotNull($hit);
        self::assertSame(65536, strlen($hit['content']), 'content must be truncated to the cap');
    }

    public function test_per_scope_file_cap_blocks_a_flood(): void
    {
        $s = $this->store();
        for ($i = 0; $i < 64; $i++) {
            self::assertTrue($s->capture('src-a', "/f{$i}.txt", 'x', 'text/plain'), "file {$i} within cap");
        }
        self::assertFalse($s->capture('src-a', '/f64.txt', 'x', 'text/plain'), 'the 65th file for one source is refused');
        // A different source is unaffected.
        self::assertTrue($s->capture('src-b', '/g.txt', 'x', 'text/plain'));
        // An overwrite of an existing path still works at the cap.
        self::assertTrue($s->capture('src-a', '/f0.txt', 'y', 'text/plain'), 'overwriting an existing file at the cap is allowed');
    }

    public function test_empty_scope_or_path_is_rejected(): void
    {
        $s = $this->store();
        self::assertFalse($s->capture('', '/p.txt', 'x', 'text/plain'));
        self::assertFalse($s->capture('src-a', '', 'x', 'text/plain'));
        self::assertNull($s->verify('', '/p.txt'));
        self::assertNull($s->verify('src-a', ''));
    }

    public function test_fail_open_on_unwritable_store(): void
    {
        // A path under an existing FILE (not a dir) cannot open — the store must fail open, never throw.
        $file = sys_get_temp_dir() . '/fp0467-file-' . bin2hex(random_bytes(6));
        file_put_contents($file, 'x');
        $this->tmp[] = $file;
        $s = new WriteCaptureStore($file . '/nope/x.sqlite', function (): int { return $this->now; });
        self::assertFalse($s->capture('src-a', '/p.txt', 'x', 'text/plain'), 'broken store capture fails open (false)');
        self::assertNull($s->verify('src-a', '/p.txt'), 'broken store verify fails open (null)');
    }
}
