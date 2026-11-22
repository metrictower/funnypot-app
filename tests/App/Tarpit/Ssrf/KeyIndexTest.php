<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Storage\SsrfKeyIndex;
use Funnypot\App\Tarpit\ConfigDump;
use Funnypot\App\Tarpit\Ssrf\KeyIndexBuilder;
use PDO;
use PHPUnit\Framework\TestCase;

final class KeyIndexTest extends TestCase
{
    private const SEED = 4242;
    private const FSKEY = 'fs-key-test';
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/fp0816idx_' . bin2hex(random_bytes(5));
        mkdir($this->dir, 0700, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $f) {
            unlink($f);
        }
        rmdir($this->dir);
    }

    private function index(int $cap, bool $pointers = false, string $fsKey = self::FSKEY, string $stamp = 'b1'): SsrfKeyIndex
    {
        return new SsrfKeyIndex($this->dir . '/idx.sqlite', 'idx-key', new KeyIndexBuilder(self::SEED, $fsKey, $cap), SsrfKeyIndex::deployId('idx-key', self::SEED, $cap, $pointers, $stamp));
    }

    /** @return int the number of advance() calls until complete */
    private static function build(SsrfKeyIndex $i, int $now = 1000, int $max = 400): int
    {
        for ($n = 1; $n <= $max; $n++) {
            $i->advance($now);
            if ($i->complete()) {
                return $n;
            }
        }

        return -1;
    }

    public function test_slices_are_bounded(): void
    {
        $i = $this->index(2 << 20);
        $i->advance(1000);
        self::assertSame(0, $i->slicesRun, 'the first step is the version check alone');
        for ($n = 0; $n < 3; $n++) {
            $before = $i->sectionsRun;
            $i->advance(1000);
            self::assertLessThanOrEqual(KeyIndexBuilder::SLICE_SECTIONS, $i->sectionsRun - $before);
        }
        self::assertSame(3, $i->slicesRun, 'one slice per step at most');
    }

    public function test_completes_after_the_expected_slices(): void
    {
        $cap = 2 << 20;
        $b = new KeyIndexBuilder(self::SEED, self::FSKEY, $cap);
        $i = $this->index($cap);
        self::assertFalse($i->complete());
        $steps = self::build($i);
        self::assertSame(1 + (int) ceil($b->sections() / KeyIndexBuilder::SLICE_SECTIONS) + 1, $steps, 'the version check, slice 0, then the section slices');
        self::assertSame($b->slices(), $i->slicesRun);
        $f = (new ConfigDump(self::SEED))->sectionFacts($b->sections() - 1);
        self::assertTrue($i->contains('aws', $f['awsKey']), 'the last section the cap can serve is indexed');
        self::assertTrue($i->contains('host', $f['cacheHost']));
        foreach ($b->smallByFamily() as $family => $keys) {
            self::assertNotSame([], $keys, $family);
            foreach ($keys as $k) {
                self::assertTrue($i->contains((string) \Funnypot\App\Tarpit\Ssrf\ServedKeys::kindOf($k), $k), "{$family} {$k}");
            }
        }
        self::assertFalse($i->contains('aws', 'AK' . 'IAZZZZZZZZZZZZZZZZZQ'));
        $runs = $i->slicesRun;
        $i->advance(1500);
        self::assertSame($runs, $i->slicesRun, 'a complete index does no work');
    }

    public function test_version_change_clears_and_rebuilds(): void
    {
        $cap = 256 << 10;
        $f = (new ConfigDump(self::SEED))->sectionFacts(3);
        $a = $this->index($cap);
        self::build($a);
        self::assertTrue($a->contains('aws', $f['awsKey']));
        $tagA = (int) $a->stats()['vtag'];
        foreach ([['cap', $this->index(512 << 10)], ['pointer flag', $this->index($cap, true)], ['generator fingerprint', $this->index($cap, false, 'another-fs-key')]] as [$why, $next]) {
            $next->advance(2000);
            self::assertFalse($next->complete(), "{$why}: a new version starts incomplete");
            self::assertFalse($next->contains('aws', $f['awsKey']), "{$why}: the old rows are never read");
            self::assertGreaterThan($tagA, (int) $next->stats()['vtag'], $why);
            self::build($next, 2000);
            self::assertTrue($next->contains('aws', $f['awsKey']), "{$why}: rebuilt");
            $tagA = (int) $next->stats()['vtag'];
            $stats = $next->stats();
            self::assertSame($stats['rows'], $stats['all_rows'], "{$why}: old rows deleted in bounded chunks");
        }
        $same = $this->index($cap, false, 'another-fs-key');
        $same->advance(2000 + 10);
        self::assertTrue($same->complete(), 'the same deploy within the hour reuses the index');
    }

    public function test_busy_lock_skips_without_waiting(): void
    {
        $i = $this->index(256 << 10);
        $i->advance(1000);
        $other = new PDO('sqlite:' . $this->dir . '/idx.sqlite');
        $other->exec('BEGIN IMMEDIATE');
        $t = hrtime(true);
        $i->advance(1000);
        $ms = (hrtime(true) - $t) / 1e6;
        $other->exec('ROLLBACK');
        self::assertTrue($i->busySkipped);
        self::assertSame(0, $i->slicesRun);
        self::assertLessThan(50, $ms, 'skipped, not waited');
        $i->advance(1000);
        self::assertSame(1, $i->slicesRun, 'the next request builds');
    }

    public function test_bytes_per_section_is_bounded(): void
    {
        $cap = 8 << 20;
        $i = $this->index($cap);
        self::assertGreaterThan(0, self::build($i));
        $db = $i->db();
        $db->exec('PRAGMA wal_checkpoint(TRUNCATE)');
        clearstatcache();
        $bytes = filesize($this->dir . '/idx.sqlite');
        $sections = (new KeyIndexBuilder(self::SEED, self::FSKEY, $cap))->sections();
        $per = $bytes / $sections;
        fwrite(STDERR, sprintf("\nkey index at 8 MB: %d sections, %d bytes, %.1f B per section\n", $sections, $bytes, $per));
        self::assertLessThanOrEqual(120, $per);
    }
}
