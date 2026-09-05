<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\Llm\LlmGenBudget;
use PHPUnit\Framework\TestCase;

/**
 * The global generations/hour ledger: counts across instances (all php-fpm workers), trips exactly
 * at the cap, resets on the hour bucket, prunes old buckets, and fails CLOSED when its store is
 * unreadable — an unverifiable budget must never become unbounded spend.
 */
final class LlmGenBudgetTest extends TestCase
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
        }
        $this->tmp = [];
    }

    private function dbPath(): string
    {
        $p = sys_get_temp_dir() . '/fp_genbudget_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    private function budget(string $path, int $perHour): LlmGenBudget
    {
        return new LlmGenBudget($path, $perHour, fn (): int => $this->now);
    }

    public function test_charge_and_exhausted_around_the_cap(): void
    {
        $b = $this->budget($this->dbPath(), 3);
        self::assertFalse($b->exhausted());
        self::assertSame(0, $b->spent());
        $b->charge();
        $b->charge();
        self::assertFalse($b->exhausted());
        self::assertSame(2, $b->spent());
        $b->charge();
        self::assertTrue($b->exhausted());
        self::assertSame(3, $b->spent());
        $b->charge();   // over the cap: still just counting, never a throw
        self::assertTrue($b->exhausted());
        self::assertSame(4, $b->spent());
    }

    public function test_cap_is_shared_across_instances_on_one_file(): void
    {
        $path = $this->dbPath();
        $a = $this->budget($path, 2);
        $b = $this->budget($path, 2);
        $a->charge();
        $b->charge();
        self::assertTrue($a->exhausted());
        self::assertTrue($b->exhausted());
        self::assertSame(2, $b->spent());
    }

    public function test_cap_floor_is_one(): void
    {
        $b = $this->budget($this->dbPath(), 0);
        self::assertFalse($b->exhausted());
        $b->charge();
        self::assertTrue($b->exhausted());
    }

    public function test_hour_bucket_rollover_resets_the_spend(): void
    {
        $b = $this->budget($this->dbPath(), 2);
        $b->charge();
        $b->charge();
        self::assertTrue($b->exhausted());

        $this->now += 3600;
        self::assertFalse($b->exhausted());
        self::assertSame(0, $b->spent());
        $b->charge();
        self::assertSame(1, $b->spent());

        // Stepping back into the spent hour sees its ledger again (buckets are independent).
        $this->now -= 3600;
        self::assertTrue($b->exhausted());
    }

    public function test_prune_ledger_drops_only_old_buckets(): void
    {
        $b = $this->budget($this->dbPath(), 10);
        $b->charge();                       // bucket t0
        $this->now += 2 * 3600;
        $b->charge();                       // bucket t0+2h
        $this->now += 2 * 3600;
        $b->charge();                       // bucket t0+4h (current)

        self::assertSame(1, $b->pruneLedger(3), 'only the bucket older than keepHours goes');
        self::assertSame(1, $b->spent(), 'the current bucket is untouched');
        self::assertSame(0, $b->pruneLedger(3));
    }

    public function test_fails_closed_when_the_ledger_cannot_be_opened(): void
    {
        $b = $this->budget('/dev/null/no-such-dir/budget.sqlite', 1000);
        self::assertTrue($b->exhausted(), 'an unverifiable budget spends nothing');
        $b->charge();                       // best-effort: no throw
        self::assertSame(0, $b->pruneLedger());
    }
}
