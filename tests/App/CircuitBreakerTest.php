<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\Llm\CircuitBreaker;
use PDO;
use PHPUnit\Framework\TestCase;

/**
 * The sidecar circuit breaker's state machine across worker instances sharing one SQLite file:
 * closed → open after the threshold, shed for the cooldown, then exactly ONE half-open probe while
 * peers keep shedding; a probe success closes it for everyone, a probe failure re-opens it at once.
 * The failure count is an atomic upsert (proved under real process concurrency), a stale half-open
 * heals itself, a legacy table upgrades in place, and broken storage fails OPEN.
 */
final class CircuitBreakerTest extends TestCase
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
        $p = sys_get_temp_dir() . '/fp_breaker_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    /** Two workers = two instances on one file, sharing the test clock. */
    private function breaker(string $path, int $threshold = 3, int $cooldown = 30): CircuitBreaker
    {
        return new CircuitBreaker($path, $threshold, $cooldown, fn (): int => $this->now);
    }

    /** @return array{failures:int,until:string,state:string} the raw row */
    private function row(string $path): array
    {
        $db = new PDO('sqlite:' . $path);
        $r = $db->query("SELECT failures, until, state FROM breaker WHERE k = 'llm'")->fetch(PDO::FETCH_ASSOC);

        return ['failures' => (int) $r['failures'], 'until' => (string) $r['until'], 'state' => (string) $r['state']];
    }

    /** Trip the breaker with $threshold failures from $b. */
    private function trip(CircuitBreaker $b, int $threshold = 3): void
    {
        for ($i = 0; $i < $threshold; $i++) {
            $b->recordFailure();
        }
    }

    public function test_closed_by_default_and_trips_at_the_threshold(): void
    {
        $path = $this->dbPath();
        $b = $this->breaker($path);
        self::assertTrue($b->allow());
        $b->recordFailure();
        $b->recordFailure();
        self::assertTrue($b->allow(), 'one under the threshold stays closed');
        self::assertSame(2, $this->row($path)['failures']);
        $b->recordFailure();
        self::assertFalse($b->allow());
        self::assertSame('open', $this->row($path)['state']);
        self::assertSame(0, $this->row($path)['failures'], 'the count resets on trip');
    }

    public function test_success_resets_the_count(): void
    {
        $path = $this->dbPath();
        $b = $this->breaker($path);
        $b->recordFailure();
        $b->recordFailure();
        $b->recordSuccess();
        $b->recordFailure();
        self::assertTrue($b->allow(), 'consecutive failures only: a success in between resets');
        self::assertSame(1, $this->row($path)['failures']);
    }

    public function test_open_sheds_every_worker_until_the_cooldown_lapses(): void
    {
        $path = $this->dbPath();
        $a = $this->breaker($path);
        $b = $this->breaker($path);
        $this->trip($a);
        self::assertFalse($a->allow());
        self::assertFalse($b->allow());
        $this->now += 29;
        self::assertFalse($a->allow());
        self::assertFalse($b->allow());
    }

    public function test_after_the_cooldown_exactly_one_worker_probes_and_the_peers_stay_shed(): void
    {
        $path = $this->dbPath();
        $a = $this->breaker($path);
        $b = $this->breaker($path);
        $this->trip($a);
        $this->now += 31;

        self::assertTrue($a->allow(), 'the first caller claims the probe');
        self::assertSame('half-open', $this->row($path)['state']);
        self::assertFalse($b->allow(), 'a peer stays shed while the probe is in flight');
        self::assertFalse($a->allow(), 'even the claimer gets exactly one probe, not a stream');
    }

    public function test_probe_success_closes_the_breaker_for_everyone(): void
    {
        $path = $this->dbPath();
        $a = $this->breaker($path);
        $b = $this->breaker($path);
        $this->trip($a);
        $this->now += 31;
        self::assertTrue($a->allow());
        $a->recordSuccess();
        self::assertTrue($b->allow());
        self::assertTrue($a->allow());
        self::assertSame('closed', $this->row($path)['state']);
    }

    public function test_probe_failure_reopens_for_a_full_cooldown_without_counting(): void
    {
        $path = $this->dbPath();
        $a = $this->breaker($path);
        $b = $this->breaker($path);
        $this->trip($a);
        $this->now += 31;
        self::assertTrue($a->allow());
        $a->recordFailure();                                  // the probe found the sidecar still dead
        self::assertSame('open', $this->row($path)['state']);
        self::assertSame(0, $this->row($path)['failures'], 'a probe failure does not count toward the threshold');
        self::assertFalse($a->allow());
        self::assertFalse($b->allow());
        $this->now += 29;
        self::assertFalse($b->allow(), 'a fresh full cooldown, not the remainder of the old one');
        $this->now += 2;
        self::assertTrue($b->allow(), 'and then one probe again');
        self::assertFalse($a->allow());
    }

    public function test_stale_half_open_is_reclaimable_after_its_deadline(): void
    {
        // The probe worker died before reporting: half-open must not wedge the breaker shut.
        $path = $this->dbPath();
        $a = $this->breaker($path);
        $b = $this->breaker($path);
        $this->trip($a);
        $this->now += 31;
        self::assertTrue($a->allow());                        // claims, then (simulated) dies
        $this->now += 10;
        self::assertFalse($b->allow(), 'still inside the probe deadline');
        $this->now += 21;
        self::assertTrue($b->allow(), 'the lapsed half-open is claimed again');
        self::assertFalse($a->allow());
    }

    public function test_a_late_failure_while_open_does_not_clear_the_breaker(): void
    {
        // A request that started before the trip and fails afterwards must not reset `until`.
        $path = $this->dbPath();
        $a = $this->breaker($path);
        $b = $this->breaker($path);
        $this->trip($a);
        $b->recordFailure();
        self::assertFalse($a->allow());
        self::assertSame('open', $this->row($path)['state']);
    }

    public function test_fails_open_on_broken_storage(): void
    {
        $b = new CircuitBreaker('/dev/null/no-such-dir/breaker.sqlite', 1, 30);
        self::assertTrue($b->allow());
        $b->recordFailure();
        $b->recordSuccess();
        self::assertTrue($b->allow(), 'the breaker must never be what breaks');
    }

    public function test_legacy_table_without_the_state_column_upgrades_in_place(): void
    {
        $path = $this->dbPath();
        $db = new PDO('sqlite:' . $path);
        $db->exec("CREATE TABLE breaker (k TEXT PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0, until TEXT NOT NULL DEFAULT '')");
        $db->prepare("INSERT INTO breaker (k, failures, until) VALUES ('llm', 0, :u)")->execute([':u' => gmdate('c', $this->now + 20)]);
        unset($db);

        $b = $this->breaker($path);
        self::assertFalse($b->allow(), 'a legacy open row (until in the future) is still honoured');
        $cols = array_column((new PDO('sqlite:' . $path))->query('PRAGMA table_info(breaker)')->fetchAll(PDO::FETCH_ASSOC), 'name');
        self::assertContains('state', $cols);
        $this->now += 21;
        self::assertTrue($b->allow());
        // From here the full state machine runs on the upgraded table.
        $this->trip($b);
        self::assertSame('open', $this->row($path)['state']);
        self::assertFalse($b->allow());
        // A second open on the same file (a later boot) survives the duplicate-column ALTER.
        self::assertFalse($this->breaker($path)->allow());
    }

    public function test_failure_count_is_atomic_across_concurrent_processes(): void
    {
        if (!function_exists('proc_open')) {
            self::markTestSkipped('proc_open unavailable');
        }
        $path = $this->dbPath();
        // Warm the schema + row in the parent so the children race only on the increment.
        $this->breaker($path, 100000)->recordSuccess();

        $autoload = dirname(__DIR__, 2) . '/vendor/autoload.php';
        $child = $path . '.child.php';
        $go = $path . '.go';
        $this->tmp[] = $child;
        $this->tmp[] = $go;
        $workers = 8;
        $perWorker = 25;
        file_put_contents($child, "<?php\n"
            . 'require ' . var_export($autoload, true) . ";\n"
            . '$b = new Funnypot\App\Llm\CircuitBreaker(' . var_export($path, true) . ", 100000, 30);\n"
            . 'touch(' . var_export($path, true) . " . '.ready.' . \$argv[1]);\n"
            . 'while (!file_exists(' . var_export($go, true) . ")) { usleep(200); }\n"
            . "for (\$i = 0; \$i < {$perWorker}; \$i++) { \$b->recordFailure(); }\n"
            . 'file_put_contents(' . var_export($path, true) . " . '.out.' . \$argv[1], 'done');\n");

        $procs = [];
        for ($i = 0; $i < $workers; $i++) {
            $this->tmp[] = $path . '.ready.' . $i;
            $this->tmp[] = $path . '.out.' . $i;
            $p = proc_open([PHP_BINARY, $child, (string) $i], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            self::assertIsResource($p);
            $procs[] = [$p, $pipes];
        }
        // Barrier: release every worker together so the increments genuinely overlap.
        $deadline = microtime(true) + 20;
        do {
            $ready = 0;
            for ($i = 0; $i < $workers; $i++) {
                if (file_exists($path . '.ready.' . $i)) {
                    $ready++;
                }
            }
            if ($ready === $workers) {
                break;
            }
            usleep(1000);
        } while (microtime(true) < $deadline);
        self::assertSame($workers, $ready, 'all child processes must reach the barrier');
        touch($go);
        foreach ($procs as [$p, $pipes]) {
            foreach ($pipes as $pipe) {
                @stream_get_contents($pipe);
                @fclose($pipe);
            }
            proc_close($p);
        }
        for ($i = 0; $i < $workers; $i++) {
            self::assertSame('done', @file_get_contents($path . '.out.' . $i), "worker $i did not finish");
        }

        self::assertSame($workers * $perWorker, $this->row($path)['failures'], 'a read-then-write increment loses counts under concurrency');
    }
}
