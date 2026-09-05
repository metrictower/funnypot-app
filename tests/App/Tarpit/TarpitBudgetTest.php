<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit;

use Funnypot\App\Storage\TarpitBudget;
use PHPUnit\Framework\TestCase;

/**
 * The cross-worker caps (FP-0245a): the concurrency ceiling + per-IP=1 under a burst, fail-closed on
 * a storage fault, the hour-bucketed budget ledger, the SHORT-TTL inline/cron reaper, and the
 * guard-first seam that is the ONLY per-IP backstop on the gate-exempt tarpit routes.
 */
final class TarpitBudgetTest extends TestCase
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

    private function path(): string
    {
        $p = sys_get_temp_dir() . '/fp_tarpit_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    /** A budget with a fixed clock so slot TTLs and hour buckets are deterministic. */
    private function budget(string $path, array $over = []): TarpitBudget
    {
        $defaults = [
            'enabled' => true,
            'maxConcurrent' => 4,
            'maxPerIp' => 1,
            'bytesPerIpHr' => 64 * 1024 * 1024,
            'wallPerIpHrMs' => 120 * 1000,
            'globalBytesHr' => 1024 * 1024 * 1024,
            'pagesPerIpHr' => 2000,
            'slotTtlSecs' => 15,
            'clock' => static fn (): int => 1_000_000,
        ];
        $c = array_merge($defaults, $over);

        return new TarpitBudget(
            $path,
            $c['enabled'],
            $c['maxConcurrent'],
            $c['maxPerIp'],
            $c['bytesPerIpHr'],
            $c['wallPerIpHrMs'],
            $c['globalBytesHr'],
            $c['pagesPerIpHr'],
            $c['slotTtlSecs'],
            $c['clock']
        );
    }

    /** Acceptance §2: with MAX_CONCURRENT=4, 8 acquires => exactly 4 WON, 4 FULL; inflight == 4. */
    public function test_global_concurrency_cap_is_a_hard_ceiling(): void
    {
        $b = $this->budget($this->path());
        $won = 0;
        $full = 0;
        for ($i = 0; $i < 8; $i++) {
            $r = $b->acquire('10.0.0.' . $i); // 8 distinct IPs so per-IP never binds first
            if ($r['status'] === TarpitBudget::WON) {
                $won++;
                self::assertNotNull($r['slot']);
            } elseif ($r['status'] === TarpitBudget::FULL) {
                $full++;
                self::assertNull($r['slot']);
            }
        }
        self::assertSame(4, $won);
        self::assertSame(4, $full);
        self::assertSame(4, $b->inflightCount());
    }

    /**
     * Acceptance §2 (cross-process): the sequential test above proves the cap ARITHMETIC on one
     * connection; this proves the `BEGIN IMMEDIATE` serialization actually holds when N real processes
     * race `acquire()` at once (a single-connection test would pass even if the transaction were
     * removed). 12 barrier-synced children on distinct IPs, cap=4 => exactly 4 WON across all
     * processes, inflight == 4. (Reviewers opus+fable both asked this be pinned before flip-on.)
     */
    public function test_global_cap_holds_across_concurrent_processes(): void
    {
        if (!function_exists('proc_open')) {
            self::markTestSkipped('proc_open unavailable');
        }
        $path = $this->path();
        // Parent creates the schema FIRST so the children attach to an existing DB — a cold first-ever
        // CREATE racing 12 writers can fail-closed to FULL (the safe direction, but it would make the
        // "exactly 4 WON" count flaky). One warm read materialises the tables.
        $warm = $this->budget($path);
        self::assertSame(0, $warm->inflightCount());

        $autoload = dirname(__DIR__, 3) . '/vendor/autoload.php';
        $child = $path . '.child.php';
        $go = $path . '.go';
        $this->tmp[] = $child;
        $this->tmp[] = $go;
        // Child: build the SAME budget (cap 4 / per-IP 1 / fixed clock), reach the barrier, then acquire
        // for its own distinct IP and record the status. It does NOT release — holding the slot is what
        // makes the cross-process ceiling observable to the parent's inflightCount().
        file_put_contents($child, "<?php\n"
            . 'require ' . var_export($autoload, true) . ";\n"
            . "use Funnypot\\App\\Storage\\TarpitBudget;\n"
            . '$b = new TarpitBudget(' . var_export($path, true)
            . ", true, 4, 1, 67108864, 120000, 1073741824, 2000, 15, static fn(): int => 1000000);\n"
            . '$ready = ' . var_export($path, true) . " . '.ready.' . \$argv[1];\n"
            . '$go = ' . var_export($go, true) . ";\n"
            . "touch(\$ready);\n"
            . "while (!file_exists(\$go)) { usleep(200); }\n"
            . "\$r = \$b->acquire('10.0.0.' . \$argv[1]);\n"
            . 'file_put_contents(' . var_export($path, true) . " . '.out.' . \$argv[1], \$r['status']);\n");

        $n = 12;
        $procs = [];
        for ($i = 0; $i < $n; $i++) {
            $this->tmp[] = $path . '.ready.' . $i;
            $this->tmp[] = $path . '.out.' . $i;
            $p = proc_open([PHP_BINARY, $child, (string) $i], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            self::assertIsResource($p);
            $procs[] = [$p, $pipes];
        }
        // Wait for every child to reach the barrier, then release them all at once.
        $deadline = microtime(true) + 15;
        $ready = 0;
        do {
            $ready = 0;
            for ($i = 0; $i < $n; $i++) {
                if (file_exists($path . '.ready.' . $i)) {
                    $ready++;
                }
            }
            if ($ready === $n) {
                break;
            }
            usleep(1000);
        } while (microtime(true) < $deadline);
        self::assertSame($n, $ready, 'all child processes must reach the barrier');
        touch($go);
        foreach ($procs as [$p, $pipes]) {
            foreach ($pipes as $pipe) {
                @stream_get_contents($pipe);
                @fclose($pipe);
            }
            proc_close($p); // blocks until the child exits
        }

        $won = 0;
        $full = 0;
        for ($i = 0; $i < $n; $i++) {
            $status = @file_get_contents($path . '.out.' . $i);
            self::assertNotFalse($status, "child $i recorded no acquire result");
            if ($status === TarpitBudget::WON) {
                $won++;
            } elseif ($status === TarpitBudget::FULL) {
                $full++;
            }
        }
        self::assertSame(4, $won, 'exactly MAX_CONCURRENT slots may be WON across all racing processes');
        self::assertSame($n - 4, $full, 'every other racer must be denied (fail-closed under contention)');
        self::assertSame(4, $warm->inflightCount(), 'the DB must hold exactly the cap in flight');
    }

    public function test_per_ip_cap_and_release_frees_the_slot(): void
    {
        $b = $this->budget($this->path());

        $first = $b->acquire('1.2.3.4');
        self::assertSame(TarpitBudget::WON, $first['status']);

        // A second slot for the SAME IP is PER_IP_FULL (distinct from a global FULL), even though 3
        // global slots remain free.
        $second = $b->acquire('1.2.3.4');
        self::assertSame(TarpitBudget::PER_IP_FULL, $second['status']);
        self::assertNull($second['slot']);
        self::assertSame(1, $b->inflightForIp('1.2.3.4'));

        // After release, that IP can acquire again.
        $b->release($first['slot']);
        self::assertSame(0, $b->inflightForIp('1.2.3.4'));
        self::assertSame(TarpitBudget::WON, $b->acquire('1.2.3.4')['status']);
    }

    public function test_release_null_is_a_noop(): void
    {
        $b = $this->budget($this->path());
        $b->release(null); // guard() returned null => nothing was taken
        self::assertSame(0, $b->inflightCount());
    }

    /** Fail-safe: a budget-store fault denies (FULL) and never throws — never a 500, never a WON. */
    public function test_fails_closed_on_unwritable_store(): void
    {
        // A path whose parent is a file, so open() throws.
        $b = $this->budget('/dev/null/nope/tarpit.sqlite');

        $r = $b->acquire('9.9.9.9');
        self::assertSame(TarpitBudget::FULL, $r['status']);
        self::assertNull($r['slot']);

        // overBudget fails closed to "over" (can't verify => shed), and guard() sheds to null.
        self::assertTrue($b->overBudget('9.9.9.9'));
        self::assertNull($b->guard('9.9.9.9'));
        // Never threw.
        self::assertSame(0, $b->inflightCount());
    }

    public function test_budget_ledger_bytes_per_ip_rolls_over_at_the_hour(): void
    {
        $now = 1_000_000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        $b = $this->budget($this->path(), ['bytesPerIpHr' => 1000, 'clock' => $clock]);

        self::assertFalse($b->overBudget('5.5.5.5'));
        $b->charge('5.5.5.5', 600, 0);
        self::assertFalse($b->overBudget('5.5.5.5'));
        $b->charge('5.5.5.5', 600, 0); // sum 1200 >= 1000
        self::assertTrue($b->overBudget('5.5.5.5'));

        // The next hour bucket starts fresh.
        $now += 3600;
        self::assertFalse($b->overBudget('5.5.5.5'));
    }

    public function test_budget_ledger_wall_and_pages_caps(): void
    {
        $b = $this->budget($this->path(), ['wallPerIpHrMs' => 500, 'pagesPerIpHr' => 3]);

        $b->charge('7.7.7.7', 0, 500, 1); // wall hits the cap
        self::assertTrue($b->overBudget('7.7.7.7'));

        $b2 = $this->budget($this->path(), ['pagesPerIpHr' => 3]);
        $b2->charge('8.8.8.8', 0, 0, 3); // pages hit the cap
        self::assertTrue($b2->overBudget('8.8.8.8'));
    }

    public function test_global_bytes_cap_sheds_a_fresh_ip(): void
    {
        $b = $this->budget($this->path(), ['globalBytesHr' => 2000]);
        $b->charge('1.1.1.1', 1500, 0);
        $b->charge('2.2.2.2', 600, 0); // global sum 2100 >= 2000
        // A fresh IP with zero spend is still shed because the aggregate egress ceiling is reached.
        self::assertTrue($b->overBudget('3.3.3.3'));
    }

    public function test_reap_clears_stale_slots_only(): void
    {
        $now = 1_000_000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        $b = $this->budget($this->path(), ['clock' => $clock, 'slotTtlSecs' => 15]);

        $b->acquire('4.4.4.4');
        self::assertSame(1, $b->inflightCount());

        // Still fresh (within TTL) — reap spares it.
        $now += 10;
        self::assertSame(0, $b->reap());
        self::assertSame(1, $b->inflightCount());

        // Past the SHORT TTL — reap clears it.
        $now += 20; // 30s old, TTL 15s
        self::assertSame(1, $b->reap());
        self::assertSame(0, $b->inflightCount());
    }

    /** SHOULD-FIX 5: acquire self-reaps a wedged slot inline, so the pool never stays full past a TTL. */
    public function test_acquire_self_reaps_wedged_slot_inline(): void
    {
        $now = 1_000_000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        // A 1-slot pool, wedged by a crashed holder.
        $b = $this->budget($this->path(), ['maxConcurrent' => 1, 'clock' => $clock, 'slotTtlSecs' => 15]);
        $b->acquire('bad-holder');
        self::assertSame(TarpitBudget::FULL, $b->acquire('newcomer')['status']); // pool full, no crash yet

        // The holder "crashes" (never released); one TTL later a newcomer's acquire self-reaps it
        // inline and wins — without waiting for the retention cron.
        $now += 30;
        self::assertSame(TarpitBudget::WON, $b->acquire('newcomer')['status']);
        self::assertSame(1, $b->inflightForIp('newcomer'));
    }

    public function test_prune_ledger_drops_old_buckets(): void
    {
        $now = 1_000_000;
        $clock = static function () use (&$now): int {
            return $now;
        };
        $b = $this->budget($this->path(), ['clock' => $clock]);
        $b->charge('a', 10, 0);        // old bucket
        $now += 3600 * 5;              // 5 hours later
        $b->charge('b', 10, 0);        // current bucket
        self::assertGreaterThanOrEqual(1, $b->pruneLedger(3)); // keep last 3h => the old row drops
    }

    /**
     * The check-then-act between overBudget() and acquire() is documented on guard(): two same-IP
     * requests can BOTH read "under budget" before either is charged (charge() lands post-serve), but
     * acquire()'s per-IP concurrency cap bounds how many of them get to serve — so a just-crossed hourly
     * ledger can be overshot by at most maxPerIp responses per IP. Pins the bound at the default (1) and
     * shows it widening with maxPerIp, so a future bump is a visible, deliberate trade.
     */
    public function test_ledger_overshoot_is_bounded_by_max_per_ip(): void
    {
        // Per-IP hourly page budget of 1 with nothing charged yet: both racing guard() reads pass the
        // overBudget() check, but only ONE wins a slot (per-IP = 1) — the other is denied before serving.
        $b = $this->budget($this->path(), ['pagesPerIpHr' => 1]);
        $first = $b->guard('9.9.9.9');
        $second = $b->guard('9.9.9.9');
        self::assertNotNull($first, 'the first racer serves');
        self::assertNull($second, 'the second racer is denied by the per-IP slot cap, not by the (unbilled) ledger');
        self::assertSame(1, $b->inflightForIp('9.9.9.9'), 'at most maxPerIp (1) responses can overshoot the ledger');

        // The winner's post-serve charge closes the window: every later guard() sheds on the ledger.
        $b->charge('9.9.9.9', 0, 0, 1);
        $b->release($first);
        self::assertTrue($b->overBudget('9.9.9.9'));
        self::assertNull($b->guard('9.9.9.9'));

        // Raising maxPerIp widens the overshoot proportionally — the documented trade, not a bug.
        $wide = $this->budget($this->path(), ['pagesPerIpHr' => 1, 'maxPerIp' => 3]);
        $won = 0;
        for ($i = 0; $i < 5; $i++) {
            if ($wide->guard('8.8.8.8') !== null) {
                $won++;
            }
        }
        self::assertSame(3, $won, 'the overshoot bound equals maxPerIp');
    }

    /**
     * Guard-first invariant (plan-review SHOULD-FIX 3): guard() is the ONLY seam that both checks the
     * budget and takes a slot, and it fails closed in every branch. On the gate-exempt tarpit routes
     * nothing may dispatch work without a slot from guard() — so a null from guard() is "shed to a
     * bounded 404", and a slot is handed back ONLY on master-on + under-budget + won.
     */
    public function test_guard_is_the_fail_closed_entry_seam(): void
    {
        // Master switch OFF => inert: no slot, nothing taken.
        $off = $this->budget($this->path(), ['enabled' => false]);
        self::assertNull($off->guard('1.2.3.4'));
        self::assertSame(0, $off->inflightCount());

        // Master ON, under budget, slot free => a real held slot id, and it is actually held.
        $on = $this->budget($this->path());
        $slot = $on->guard('1.2.3.4');
        self::assertNotNull($slot);
        self::assertSame(1, $on->inflightCount());
        $on->release($slot);
        self::assertSame(0, $on->inflightCount());

        // Over budget => shed, and NO slot is taken (budget is checked before a slot is acquired).
        $over = $this->budget($this->path(), ['bytesPerIpHr' => 100]);
        $over->charge('5.5.5.5', 200, 0);
        self::assertNull($over->guard('5.5.5.5'));
        self::assertSame(0, $over->inflightCount());

        // Global concurrency full => guard sheds (per-IP=1, so use distinct IPs to fill the pool).
        $full = $this->budget($this->path(), ['maxConcurrent' => 2]);
        self::assertNotNull($full->guard('a'));
        self::assertNotNull($full->guard('b'));
        self::assertNull($full->guard('c')); // pool full => bounded 404
    }
}
