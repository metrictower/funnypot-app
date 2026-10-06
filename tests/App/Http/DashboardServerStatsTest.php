<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Http\ServerStorageTelemetry;
use PHPUnit\Framework\TestCase;

final class DashboardServerStatsTest extends TestCase
{
    /** @var string[] */
    private array $tmp = [];

    protected function tearDown(): void
    {
        foreach (array_reverse($this->tmp) as $p) {
            if (is_file($p)) {
                @unlink($p);
            } elseif (is_dir($p)) {
                @rmdir($p);
            }
        }
    }

    private function tmpBase(): string
    {
        $base = sys_get_temp_dir() . '/fp0209-' . bin2hex(random_bytes(6));
        @mkdir($base . '/recordings', 0700, true);
        @mkdir($base . '/quarantine', 0700, true);
        $this->tmp[] = $base . '/recordings';
        $this->tmp[] = $base . '/quarantine';
        $this->tmp[] = $base;

        return $base;
    }

    private function writeFile(string $path, int $bytes): void
    {
        file_put_contents($path, str_repeat('x', $bytes));
        $this->tmp[] = $path;
    }

    private function probe(?int $free, ?int $total): callable
    {
        return static fn (string $p): array => ['free' => $free, 'total' => $total];
    }

    public function test_reports_recordings_quarantine_and_database_footprints(): void
    {
        $base = $this->tmpBase();
        $this->writeFile($base . '/recordings/a.wav', 100);
        $this->writeFile($base . '/recordings/b.ulaw', 50);
        $this->writeFile($base . '/quarantine/shell.war', 200);
        $db = $base . '/hits.sqlite';
        $this->writeFile($db, 1234);

        $t = new ServerStorageTelemetry($base, $db, $this->probe(10_000_000_000, 100_000_000_000));
        $s = $t->collect();

        self::assertSame(150, $s['recordings_bytes']);
        self::assertSame(2, $s['recordings_count']);
        self::assertSame(200, $s['quarantine_bytes']);
        self::assertSame(1, $s['quarantine_count']);
        self::assertSame(1234, $s['database_bytes']);
        self::assertSame(10_000_000_000, $s['disk_free_bytes']);
        self::assertSame(100_000_000_000, $s['disk_total_bytes']);
        self::assertSame(90, $s['disk_used_percent']); // (100-10)/100
        self::assertTrue($s['low_disk']); // 10/100 = 10% free, under the 15% threshold
    }

    public function test_used_percent_and_all_keys_present(): void
    {
        $base = $this->tmpBase();
        $t = new ServerStorageTelemetry($base, $base . '/none.sqlite', $this->probe(25_000_000_000, 100_000_000_000));
        $s = $t->collect();
        foreach ([
            'disk_free_bytes', 'disk_total_bytes', 'disk_used_percent', 'recordings_bytes',
            'recordings_count', 'database_bytes', 'quarantine_bytes', 'quarantine_count', 'low_disk',
        ] as $k) {
            self::assertArrayHasKey($k, $s);
        }
        self::assertSame(75, $s['disk_used_percent']);
        self::assertSame(0, $s['database_bytes']); // missing db file -> 0, not a fault
        self::assertSame(0, $s['recordings_count']);
    }

    public function test_low_disk_true_under_2gb_even_when_percent_is_fine(): void
    {
        // 1 GiB free of a 1 TiB disk: 0.1% used-wise fine on fraction? No — fraction is 0.1% free < 15%.
        // Use a huge disk so the FRACTION is healthy but the ABSOLUTE free is under 2 GiB.
        $free = 1_000_000_000;            // ~0.93 GiB, under the 2 GiB floor
        $total = 1_000_000_000_000_000;   // ~0.9 PiB, so fraction is tiny-but-that's-also-<15%
        self::assertTrue(ServerStorageTelemetry::isLowDisk($free, $total));
    }

    public function test_low_disk_true_under_15_percent(): void
    {
        $free = 10_000_000_000;   // 10 GB (over the 2 GiB floor)
        $total = 100_000_000_000; // 100 GB -> 10% free < 15%
        self::assertTrue(ServerStorageTelemetry::isLowDisk($free, $total));
    }

    public function test_low_disk_false_when_healthy(): void
    {
        $free = 50_000_000_000;   // 50 GB, > 2 GiB and 50% free
        $total = 100_000_000_000;
        self::assertFalse(ServerStorageTelemetry::isLowDisk($free, $total));
    }

    public function test_low_disk_false_when_disk_unknowable(): void
    {
        self::assertFalse(ServerStorageTelemetry::isLowDisk(null, null));
        self::assertFalse(ServerStorageTelemetry::isLowDisk(100, 0));
    }

    public function test_missing_storage_dirs_degrade_to_zero_not_fault(): void
    {
        $base = sys_get_temp_dir() . '/fp0209-missing-' . bin2hex(random_bytes(6));
        $t = new ServerStorageTelemetry($base, $base . '/x.sqlite', $this->probe(null, null));
        $s = $t->collect();
        self::assertSame(0, $s['recordings_bytes']);
        self::assertSame(0, $s['quarantine_count']);
        self::assertNull($s['disk_free_bytes']);
        self::assertNull($s['disk_used_percent']);
        self::assertFalse($s['low_disk']);
    }
}
