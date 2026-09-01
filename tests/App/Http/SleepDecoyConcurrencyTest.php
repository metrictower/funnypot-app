<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use PHPUnit\Framework\TestCase;

/**
 * FP-0228 — THE self-DoS bound for the honoured-SLEEP decoy. A server-side sleep pins a php-fpm worker
 * for its whole duration, and this stack has ~16 workers across 40+ ports, so an uncapped honoured SLEEP
 * is a self-DoS. SleepDecoy is safe ONLY because the sleep happens exclusively while a TarpitBudget slot
 * is held (guard() won a slot; released in finally): a probe that cannot win a slot is served
 * immediately, never delayed. So the number of workers ever sleeping at once can never exceed
 * MAX_CONCURRENT — regardless of how many IPs attack.
 *
 * This proves it end-to-end through SleepDecoy::maybeDelay(): a barrier-synced storm of 12 distinct-IP
 * workers, each driving a real SERVED SQLi SLEEP probe through maybeDelay with a real usleep, stamps the
 * wall window it actually slept; the parent proves no instant is covered by more than MAX_CONCURRENT
 * windows. It fails if the sleep is ever applied outside a held slot (all 12 would overlap → peak 12).
 * (Precedent: {@see \Funnypot\Tests\App\Tarpit\TarpitLatencyTest::test_at_most_max_concurrent_workers_ever_sleep_at_once}.)
 */
final class SleepDecoyConcurrencyTest extends TestCase
{
    /** @var string[] */
    private array $tmp = [];

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
        if (!function_exists('proc_open')) {
            self::markTestSkipped('proc_open unavailable');
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

    public function test_at_most_max_concurrent_workers_ever_sleep_at_once(): void
    {
        $maxConcurrent = 4;
        $capMs = 500; // per-request honoured sleep, long enough that all winners' windows overlap
        $path = sys_get_temp_dir() . '/fp_sleepdecoy_storm_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $path;

        // Warm the schema in the parent so 12 cold writers don't race the first CREATE (a cold create
        // racing writers can fail-closed to FULL and skew the counts — see the 0245a concurrency test).
        $warm = new \Funnypot\App\Storage\TarpitBudget($path, true, $maxConcurrent, 1, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, 15, static fn (): int => 1_000_000);
        self::assertSame(0, $warm->inflightCount());

        $autoload = dirname(__DIR__, 3) . '/vendor/autoload.php';
        $child = $path . '.child.php';
        $go = $path . '.go';
        $this->tmp[] = $child;
        $this->tmp[] = $go;

        // The child drives the REAL SleepDecoy::maybeDelay() with a served SQLi SLEEP(2) probe. Its budget
        // uses an injected sleeper that does a REAL usleep and records the true [start,end] window; the
        // decoy uses a zero jitter so every honoured window is exactly $capMs. guard() inside maybeDelay
        // gates the sleep on a won slot, so a shed worker records NO window (SKIP).
        file_put_contents($child, "<?php\n"
            . 'require ' . var_export($autoload, true) . ";\n"
            . "use Funnypot\\App\\Storage\\TarpitBudget;\n"
            . "use Funnypot\\App\\Http\\SleepDecoy;\n"
            . "use Funnypot\\App\\ThreatIntel\\AttackClassifier;\n"
            . "use Funnypot\\App\\Config\\AppConfig;\n"
            . "use Funnypot\\Core\\RequestContext;\n"
            . "\$win = null;\n"
            . '$sleeper = function (int $ms) use (&$win): void { $s = microtime(true); usleep($ms * 1000); $win = [$s, microtime(true)]; };' . "\n"
            . '$b = new TarpitBudget(' . var_export($path, true)
            . ", true, {$maxConcurrent}, 1, " . PHP_INT_MAX . ', ' . PHP_INT_MAX . ', ' . PHP_INT_MAX . ', ' . PHP_INT_MAX
            . ", 15, static fn(): int => 1000000, 0, \$sleeper);\n"
            . "putenv('FUNNYPOT_SLEEP_DECOY=1');\n"
            . "putenv('FUNNYPOT_SLEEP_PER_REQ_CAP_MS={$capMs}');\n"
            . '$cfg = AppConfig::fromEnv(sys_get_temp_dir());' . "\n"
            . '$decoy = new SleepDecoy($b, $cfg, new AttackClassifier(), static fn (int $c): int => 0);' . "\n"
            . '$ctx = new RequestContext(' . "'GET', '/products.php', 'id=1 AND SLEEP(2)', [], null);\n"
            . '$go = ' . var_export($go, true) . ";\n"
            . 'touch(' . var_export($path, true) . " . '.ready.' . \$argv[1]);\n"
            . "while (!file_exists(\$go)) { usleep(200); }\n"
            . "\$decoy->maybeDelay(\$ctx, '10.0.0.' . \$argv[1]);\n"
            . "\$out = \$win !== null ? ('SLEEP ' . \$win[0] . ' ' . \$win[1]) : 'SKIP';\n"
            . 'file_put_contents(' . var_export($path, true) . " . '.out.' . \$argv[1], \$out);\n");

        $n = 12;
        $procs = [];
        for ($i = 0; $i < $n; $i++) {
            $this->tmp[] = $path . '.ready.' . $i;
            $this->tmp[] = $path . '.out.' . $i;
            $p = proc_open([PHP_BINARY, $child, (string) $i], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            self::assertIsResource($p);
            $procs[] = [$p, $pipes];
        }

        // Barrier: wait for all children ready, then release them together to maximise any illegal overlap.
        $deadline = microtime(true) + 20;
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
            proc_close($p);
        }

        $windows = [];
        $slept = 0;
        $skipped = 0;
        for ($i = 0; $i < $n; $i++) {
            $out = @file_get_contents($path . '.out.' . $i);
            self::assertNotFalse($out, "child $i recorded no result");
            if (strncmp($out, 'SLEEP ', 6) === 0) {
                [, $s, $e] = explode(' ', $out);
                $windows[] = [(float) $s, (float) $e];
                $slept++;
            } else {
                $skipped++;
            }
        }

        // Exactly MAX_CONCURRENT workers won a slot and slept; the rest were served immediately, no delay.
        self::assertSame($maxConcurrent, $slept, 'only slot-holders may sleep');
        self::assertSame($n - $maxConcurrent, $skipped, 'every shed probe is served immediately, never delayed');

        // The core assertion: no instant is covered by more than MAX_CONCURRENT sleep windows.
        $events = [];
        foreach ($windows as [$s, $e]) {
            $events[] = [$s, 1];
            $events[] = [$e, -1];
        }
        usort($events, static function (array $a, array $b): int {
            if ($a[0] === $b[0]) {
                return $a[1] <=> $b[1];
            }

            return $a[0] <=> $b[0];
        });
        $cur = 0;
        $peak = 0;
        foreach ($events as [, $delta]) {
            $cur += $delta;
            $peak = max($peak, $cur);
        }
        self::assertLessThanOrEqual(
            $maxConcurrent,
            $peak,
            "at most MAX_CONCURRENT ({$maxConcurrent}) workers may be in a honoured SLEEP at once — a higher "
            . 'overlap means a probe slept without holding a slot (the self-DoS the decoy is gated to prevent)'
        );
    }
}
