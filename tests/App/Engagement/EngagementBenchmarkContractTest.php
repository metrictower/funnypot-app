<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Engagement;

use Funnypot\App\Bench\BenchConnection;
use Funnypot\App\Bench\EngagementBench;
use Funnypot\App\Bench\SqliteBenchConnection;
use Funnypot\App\Engagement\AnalyticsKey;
use Funnypot\App\Engagement\EngagementCaps;
use Funnypot\App\Storage\SqliteEngagementStore;
use InvalidArgumentException;
use PDO;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use RuntimeException;
use WeakReference;

require_once dirname(__DIR__, 3) . '/scripts/support/EngagementBench.php';

final class EngagementBenchmarkContractTest extends TestCase
{
    public function test_argument_grammar_is_bounded_and_defaults_are_explicit(): void
    {
        self::assertSame(['events' => 2000, 'keys' => 50, 'cold' => false], EngagementBench::parseArguments([]));
        self::assertSame(['events' => 2000, 'keys' => 50, 'cold' => true], EngagementBench::parseArguments(['--cold']));
        self::assertSame(['events' => 100000, 'keys' => 254, 'cold' => true], EngagementBench::parseArguments(['100000', '254', '--cold']));
        self::assertSame(['events' => 1000, 'keys' => 1, 'cold' => false], EngagementBench::parseArguments(['1000', '1']));
        foreach ([['999'], ['100001'], ['1000', '0'], ['1000', '255'], ['-1'], ['1e4'], ['01000'],
            ['1000 '], ['1000\n'], ['+1000'], ['--warm'], ['--cold', '1000'], ['1000', '--cold', '--cold'],
            ['1000', '50', '1'], ['/some/database.sqlite'], [1000]] as $args) {
            try {
                EngagementBench::parseArguments($args);
                self::fail('Invalid arguments accepted: ' . json_encode($args));
            } catch (InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
    }

    public function test_warm_and_cold_ownership_and_outer_timing_boundaries(): void
    {
        foreach ([false, true] as $cold) {
            $state = (object) ['ns' => 0, 'timing' => false, 'made' => 0, 'destroyed' => 0,
                'warmups' => 0, 'measured' => 0, 'metadata' => 0, 'violations' => [], 'last' => null];
            $factory = static function () use ($state, $cold): BenchConnection {
                if ($state->last !== null && $state->last->get() !== null) {
                    $state->violations[] = 'previous connection retained at next construction';
                }
                if ($state->timing !== ($cold && $state->made > 0)) {
                    $state->violations[] = 'construction outside required timing scope';
                }
                $state->made++;
                $state->ns += 200000;
                $connection = new class ($state) implements BenchConnection {
                    public function __construct(private object $state) {}
                    public function record(int $index): string
                    {
                        $this->state->ns += 100000;
                        $this->state->timing ? $this->state->measured++ : $this->state->warmups++;
                        return 'recorded';
                    }
                    public function metadata(): array
                    {
                        if ($this->state->timing) {
                            $this->state->violations[] = 'metadata inside timed sample';
                        }
                        $this->state->metadata++;
                        $this->state->ns += 7000000;
                        return ['synchronous' => '1', 'busy_timeout_ms' => 5];
                    }
                    public function __destruct()
                    {
                        if ($this->state->timing) {
                            $this->state->violations[] = 'destruction inside timed sample';
                        }
                        $this->state->destroyed++;
                        $this->state->ns += 4000000;
                    }
                };
                $state->last = WeakReference::create($connection);
                return $connection;
            };
            $timer = static function () use ($state): int {
                $state->timing = !$state->timing;
                return $state->ns;
            };
            $advance = static function (int $index) use ($state): void {
                if ($state->timing) {
                    $state->violations[] = 'clock advance included in timing';
                }
                $state->ns += 9000000;
            };
            $report = EngagementBench::measure(1000, 50, $cold, $factory, $advance, $timer);
            self::assertSame([], $state->violations);
            self::assertSame($cold ? 1001 : 1, $state->made);
            self::assertSame($state->made, $state->destroyed);
            self::assertNull($state->last->get());
            self::assertSame(200, $state->warmups);
            self::assertSame(1000, $state->measured);
            self::assertSame(1, $state->metadata);
            self::assertSame($cold ? 0.3 : 0.1, $report['p95_ms']);
            self::assertSame($cold ? 'connection-cold-existing-db' : 'warm', $report['mode']);
            self::assertSame(1000, $report['measured_count']);
            self::assertSame(200, array_sum($report['warmup_statuses']));
            self::assertSame(1000, array_sum($report['statuses']));
            self::assertSame($state->made, $report['connection_constructions']);
            self::assertSame('1', $report['synchronous']);
            self::assertSame(5, $report['busy_timeout_ms']);
            self::assertTrue($report['success']);
            self::assertSame(0, $report['exit_code']);
        }
    }

    public function test_all_outcomes_count_and_fast_fault_shed_disabled_runs_never_pass(): void
    {
        foreach (['fault', 'shed', 'disabled'] as $status) {
            $report = $this->fakeReport([$status], 100000);
            self::assertSame(1000, $report['statuses'][$status]);
            self::assertSame(1000, array_sum($report['statuses']));
            self::assertSame(1000, $report['drops']);
            self::assertTrue($report['within_budget']);
            self::assertFalse($report['healthy']);
            self::assertFalse($report['success']);
            self::assertSame(1, $report['exit_code']);
        }
        $report = $this->fakeReport(EngagementBench::STATUSES, 200000);
        self::assertSame(['recorded' => 250, 'shed' => 250, 'fault' => 250, 'disabled' => 250], $report['statuses']);
        self::assertSame(750, $report['drops']);
        self::assertSame(0.2, $report['p95_ms']);
    }

    public function test_budget_uses_unrounded_values_and_is_separate_from_health(): void
    {
        $report = $this->fakeReport(['recorded'], 5000001);
        self::assertSame(5.0, $report['p95_ms']);
        self::assertFalse($report['within_budget']);
        self::assertTrue($report['healthy']);
        self::assertFalse($report['success']);
        self::assertSame(1, $report['exit_code']);
        self::assertSame(0, $this->fakeReport(['recorded'], 5000000)['exit_code']);
    }

    public function test_unknown_status_and_bad_timer_are_harness_errors_not_acceptance(): void
    {
        foreach ([['surprise', 1], ['recorded', -1], ['recorded', NAN], ['recorded', INF]] as [$status, $duration]) {
            try {
                $this->fakeReport([$status], $duration);
                self::fail('Malformed run reported a result.');
            } catch (RuntimeException) {
                self::addToAssertionCount(1);
            }
        }
    }

    public function test_actual_cold_connections_share_only_the_prepared_database_and_report_own_pragmas(): void
    {
        $dir = sys_get_temp_dir() . '/fp_bench_contract_' . bin2hex(random_bytes(8));
        self::assertTrue(mkdir($dir, 0700));
        $path = $dir . '/engagement.sqlite';
        $key = AnalyticsKey::fromRaw(str_repeat('b', 32));
        $caps = new EngagementCaps();
        $clock = static fn (): int => 1700000000;
        $previous = null;
        try {
            for ($i = 0; $i < 2; $i++) {
                if ($previous !== null) {
                    self::assertNull($previous->get(), 'Previous actual PDO must have been released.');
                }
                $connection = new SqliteBenchConnection($path, $caps, $key, $clock, 50);
                self::assertSame('recorded', $connection->record($i));
                $store = (new ReflectionProperty(SqliteBenchConnection::class, 'store'))->getValue($connection);
                $db = (new ReflectionProperty(SqliteEngagementStore::class, 'db'))->getValue($store);
                self::assertInstanceOf(PDO::class, $db);
                self::assertSame(realpath($path), $db->query('PRAGMA database_list')->fetch(PDO::FETCH_ASSOC)['file']);
                $metadata = $connection->metadata();
                self::assertSame('wal', $metadata['journal_mode']);
                self::assertSame('1', $metadata['synchronous']);
                self::assertSame(5, $metadata['busy_timeout_ms']);
                self::assertSame($i + 1, (int) $db->query('SELECT COUNT(*) FROM engagement_events')->fetchColumn());
                self::assertNotSame('', $metadata['sqlite']);
                $previous = WeakReference::create($db);
                unset($connection, $store, $db);
            }
            self::assertNull($previous->get());
        } finally {
            unset($connection, $store, $db);
            foreach (['', '-wal', '-shm', '-journal'] as $suffix) {
                if (file_exists($path . $suffix)) {
                    unlink($path . $suffix);
                }
            }
            rmdir($dir);
        }
    }

    public function test_cli_argument_and_setup_failures_exit_two_without_creating_files(): void
    {
        // Two bounded CLI invocations, never a process per event; no listener, service or real database.
        $dir = sys_get_temp_dir() . '/fp_bench_cli_' . bin2hex(random_bytes(8));
        self::assertTrue(mkdir($dir, 0700));
        try {
            foreach ([[$dir, ['999']], [$dir . '/missing', ['1000']]] as [$tempDir, $args]) {
                $process = proc_open([PHP_BINARY, '-d', 'memory_limit=64M', '-d', 'max_execution_time=5',
                    '-d', 'sys_temp_dir=' . $tempDir, dirname(__DIR__, 3) . '/scripts/engagement-bench.php', ...$args],
                    [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
                self::assertIsResource($process);
                foreach ($pipes as $pipe) {
                    stream_set_blocking($pipe, false);
                }
                $out = $err = '';
                $deadline = hrtime(true) + 5_000_000_000;
                try {
                    do {
                        $out .= stream_get_contents($pipes[1]);
                        $err .= stream_get_contents($pipes[2]);
                        $status = proc_get_status($process);
                        if (strlen($out) + strlen($err) > 4096 || hrtime(true) > $deadline) {
                            self::fail('CLI exceeded five-second / 4 KiB test envelope.');
                        }
                        if ($status['running']) {
                            usleep(1000);
                        }
                    } while ($status['running']);
                    $out .= stream_get_contents($pipes[1]);
                    $err .= stream_get_contents($pipes[2]);
                    self::assertSame(2, $status['exitcode']);
                    self::assertSame('', $out);
                    self::assertStringContainsString('argument/setup/harness error', $err);
                } finally {
                    if (proc_get_status($process)['running']) {
                        proc_terminate($process, 9);
                    }
                    foreach ($pipes as $pipe) {
                        fclose($pipe);
                    }
                    proc_close($process);
                }
                self::assertSame(['.', '..'], scandir($dir));
            }
        } finally {
            rmdir($dir);
        }
    }

    private function fakeReport(array $statuses, int|float $duration): array
    {
        $factory = static fn (): BenchConnection => new class ($statuses) implements BenchConnection {
            public function __construct(private array $statuses) {}
            public function record(int $index): string { return $this->statuses[$index % count($this->statuses)]; }
            public function metadata(): array { return []; }
        };
        $tick = 0;
        $timer = static function () use (&$tick, $duration): int|float { return $tick++ % 2 === 0 ? 0 : $duration; };
        return EngagementBench::measure(1000, 50, false, $factory, static function (int $i): void {}, $timer);
    }
}
