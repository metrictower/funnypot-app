<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit;

use Funnypot\App\AiApi\StreamEmitter;
use Funnypot\App\Http\PolluterController;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\Storage\TarpitBudget;
use Funnypot\App\Tarpit\LogRabbitHole;
use Funnypot\Core\RequestContext;
use Geo;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

/**
 * FP-0245c — the context-polluter HTTP seam's invariants (plan §"Verification — 0245c" + the shared
 * budget-gate discipline, mirroring {@see LabyrinthNavTest}): off-by-default ⇒ 404, over-cap ⇒ 404,
 * store-fault ⇒ 404 never 500, each polluter served with the right content-type, the log's Range served
 * as a 206, the slot released after every hit, and telemetry logged with the technique.
 */
final class PolluterControllerTest extends TestCase
{
    private const SEED = 4242;

    /** @var string[] */
    private array $tmp = [];

    /** The last StreamEmitter the controller created — the test's window on status/headers/body. */
    private ?StreamEmitter $last = null;

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
        $this->last = null;
    }

    private function path(string $tag): string
    {
        $p = sys_get_temp_dir() . '/fp_pol_' . $tag . '_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    /**
     * @param array<string,int> $over budget overrides
     * @return array{0:PolluterController,1:TarpitBudget,2:SqliteHitStore}
     */
    private function make(array $over = [], bool $enabled = true, ?string $budgetPath = null, int $capMb = 8): array
    {
        $factory = function (): StreamEmitter {
            // A no-op sink: begin() records status/headers without calling real header(); chunk()
            // accumulates captured() without printing. So the test reads the whole response back.
            return $this->last = new StreamEmitter(static function (string $b): void {
            }, 0);
        };
        $budget = new TarpitBudget(
            $budgetPath ?? $this->path('budget'),
            $enabled,
            $over['maxConcurrent'] ?? 4,
            $over['maxPerIp'] ?? 1,
            $over['bytesPerIpHr'] ?? 64 * 1024 * 1024,
            $over['wallPerIpHrMs'] ?? 120 * 1000,
            $over['globalBytesHr'] ?? 1024 * 1024 * 1024,
            $over['pagesPerIpHr'] ?? 2000,
            15,
        );
        $store = new SqliteHitStore($this->path('hits'));
        $geo = new Geo(sys_get_temp_dir() . '/fp-no-geo-' . uniqid());
        $ctrl = new PolluterController($store, $geo, $budget, self::SEED, $capMb, null, $factory);

        return [$ctrl, $budget, $store];
    }

    private function get(PolluterController $c, string $path, array $headers = [], string $ip = '203.0.113.9'): void
    {
        $c->handle(new RequestContext('GET', $path, '', $headers), $ip);
    }

    private function status(): int
    {
        return $this->last?->status() ?? 0;
    }

    private function body(): string
    {
        return $this->last?->captured() ?? '';
    }

    /** @return array<string,string> */
    private function headers(): array
    {
        return $this->last?->headers() ?? [];
    }

    // --- matcher -----------------------------------------------------------------------------------

    public function test_matches_only_the_four_polluter_paths(): void
    {
        [$c] = $this->make();
        foreach ([PolluterController::CONFIG_PATH, PolluterController::LOG_PATH,
            PolluterController::HOSTILE_PATH, PolluterController::SHADOW_PATH, ] as $p) {
            self::assertTrue($c->matches($p), "matches {$p}");
            self::assertTrue($c->matches($p . '?x=1'), 'query is stripped before matching');
        }
        self::assertFalse($c->matches('/admin/export'), 'the bare prefix is not a polluter');
        self::assertFalse($c->matches('/admin/audit-archive/page-000001'), 'labyrinth surface is not ours');
        self::assertFalse($c->matches('/.env'), 'honeypot bait surface is not ours');
    }

    // --- each polluter serves 200 with the right content-type --------------------------------------

    public function test_config_dump_serves_a_capped_settings_py(): void
    {
        [$c] = $this->make(capMb: 1);
        $this->get($c, PolluterController::CONFIG_PATH);

        self::assertSame(200, $this->status());
        self::assertStringContainsString('text/plain', $this->headers()['Content-Type'] ?? '');
        self::assertSame(1024 * 1024, strlen($this->body()), 'streamed body is capped to bytesPerRespMb');
        self::assertStringContainsString('settings.py', $this->body());
        self::assertStringContainsString('DATABASES', $this->body());
    }

    public function test_hostile_format_serves_small_json(): void
    {
        [$c] = $this->make();
        $this->get($c, PolluterController::HOSTILE_PATH);

        self::assertSame(200, $this->status());
        self::assertStringContainsString('application/json', $this->headers()['Content-Type'] ?? '');
        self::assertLessThan(64 * 1024, strlen($this->body()), 'the token-hostile blob is small in bytes');
        self::assertStringContainsString('{', $this->body());
    }

    public function test_shadow_bait_serves_dead_bcrypt_hashes(): void
    {
        [$c] = $this->make();
        $this->get($c, PolluterController::SHADOW_PATH);

        self::assertSame(200, $this->status());
        self::assertStringContainsString('text/plain', $this->headers()['Content-Type'] ?? '');
        $body = $this->body();
        self::assertStringContainsString('root:$2y$', $body);
        // Every bcrypt hash in the served body authenticates to nothing.
        preg_match_all('/(\$2y\$\d{2}\$[A-Za-z0-9]{53})/', $body, $m);
        self::assertNotEmpty($m[1]);
        foreach ($m[1] as $hash) {
            self::assertFalse(password_verify('anything', $hash));
            self::assertFalse(password_verify('password', $hash));
        }
    }

    public function test_log_full_body_serves_capped_plaintext_with_accept_ranges(): void
    {
        [$c] = $this->make(capMb: 1);
        $this->get($c, PolluterController::LOG_PATH);

        self::assertSame(200, $this->status());
        self::assertStringContainsString('text/plain', $this->headers()['Content-Type'] ?? '');
        self::assertSame('bytes', $this->headers()['Accept-Ranges'] ?? '', 'advertises Range support');
        self::assertSame(1024 * 1024, strlen($this->body()), 'streamed log body capped to bytesPerRespMb');
    }

    // --- Range on the log ⇒ 206 with the deep key ------------------------------------------------

    public function test_log_range_returns_206_and_can_reach_the_deep_key(): void
    {
        [$c] = $this->make();
        $log = new LogRabbitHole(self::SEED);
        $juicy = $log->juicyLineIndices();
        $line = $juicy[0];
        $start = $line * LogRabbitHole::LINE_WIDTH;
        $end = $start + LogRabbitHole::LINE_WIDTH - 1;

        $this->get($c, PolluterController::LOG_PATH, ['Range' => 'bytes=' . $start . '-' . $end]);

        self::assertSame(206, $this->status(), 'a Range request is served as 206 Partial Content');
        $cr = $this->headers()['Content-Range'] ?? '';
        self::assertStringStartsWith('bytes ' . $start . '-', $cr);
        self::assertStringContainsString('/' . $log->size(), $cr, 'Content-Range names the total size');
        self::assertStringContainsString($log->secretForLine($line), $this->body(),
            'the deep credential is reachable via Range in O(window) — no full-file scan needed');
        self::assertSame(LogRabbitHole::LINE_WIDTH, strlen($this->body()));
    }

    public function test_unsatisfiable_range_falls_back_to_full_body_not_a_500(): void
    {
        [$c] = $this->make(capMb: 1);
        $this->get($c, PolluterController::LOG_PATH, ['Range' => 'bytes=99999999999-']);
        // Start past EOF ⇒ we ignore the range and serve the (capped) full body at 200, never a 500.
        self::assertSame(200, $this->status());
        self::assertSame(1024 * 1024, strlen($this->body()));
    }

    // --- off-by-default / over-cap / fail-safe (mirror LabyrinthNavTest) ---------------------------

    public function test_off_by_default_every_polluter_404s(): void
    {
        [$c] = $this->make(enabled: false);
        foreach ([PolluterController::CONFIG_PATH, PolluterController::LOG_PATH,
            PolluterController::HOSTILE_PATH, PolluterController::SHADOW_PATH, ] as $p) {
            $this->get($c, $p);
            self::assertSame(404, $this->status(), "master switch off ⇒ bounded 404 for {$p}");
            self::assertStringContainsString('404 Not Found', $this->body());
            self::assertStringNotContainsString('settings.py', $this->body());
            self::assertStringNotContainsString('$2y$', $this->body());
        }
    }

    public function test_over_the_hourly_byte_budget_sheds_to_a_bounded_404(): void
    {
        // A tiny per-IP hourly byte budget: the first (capped) response spends it, the next sheds.
        [$c] = $this->make(['bytesPerIpHr' => 4096]);
        $this->get($c, PolluterController::CONFIG_PATH, [], '192.0.2.60');
        self::assertSame(200, $this->status(), 'first hit within budget');

        $this->get($c, PolluterController::LOG_PATH, [], '192.0.2.60');
        self::assertSame(404, $this->status(), 'over the per-IP hourly byte budget ⇒ bounded 404');
        self::assertStringContainsString('404 Not Found', $this->body());
    }

    public function test_global_concurrency_full_sheds_to_a_bounded_404(): void
    {
        $bpath = $this->path('budget');
        [$c] = $this->make(['maxConcurrent' => 1], budgetPath: $bpath);
        $occupier = new TarpitBudget($bpath, true, 1, 4, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, 15);
        $held = $occupier->acquire('10.0.0.1');
        self::assertSame(TarpitBudget::WON, $held['status']);

        $this->get($c, PolluterController::CONFIG_PATH, [], '10.0.0.2');
        self::assertSame(404, $this->status(), 'no free slot ⇒ bounded 404 (never a slow stream)');

        $occupier->release($held['slot']);
    }

    public function test_fail_safe_on_a_storage_fault_never_500s(): void
    {
        $blocker = sys_get_temp_dir() . '/fp_pol_block_' . bin2hex(random_bytes(6));
        file_put_contents($blocker, 'x');
        $this->tmp[] = $blocker;
        [$c] = $this->make(budgetPath: $blocker . '/nope/x.sqlite');

        $this->get($c, PolluterController::CONFIG_PATH);
        self::assertSame(404, $this->status(), 'a budget-store fault ⇒ bounded 404 (fail-closed), never a 500');
        self::assertStringContainsString('404 Not Found', $this->body());
    }

    // --- the slot is released after every hit ------------------------------------------------------

    public function test_slot_is_released_after_serving(): void
    {
        [$c, $budget] = $this->make();
        self::assertSame(0, $budget->inflightCount());
        $this->get($c, PolluterController::CONFIG_PATH, [], '198.51.100.77');
        self::assertSame(200, $this->status());
        self::assertSame(0, $budget->inflightCount(), 'the slot is released in a finally after the response');
    }

    // --- telemetry ---------------------------------------------------------------------------------

    public function test_each_hit_logs_wasted_budget_telemetry_with_the_technique(): void
    {
        [$c, , $store] = $this->make();
        $map = [
            PolluterController::CONFIG_PATH => 'technique=config',
            PolluterController::LOG_PATH => 'technique=log',
            PolluterController::HOSTILE_PATH => 'technique=hostile',
            PolluterController::SHADOW_PATH => 'technique=shadow',
        ];
        $i = 0;
        foreach ($map as $path => $needle) {
            $this->get($c, $path, [], '198.51.100.' . (100 + $i++));
        }
        $rows = $store->delta(0)['rows'];
        $bodies = array_map(static fn (array $r): string => (string) ($r['body'] ?? ''), $rows);
        $events = array_map(static fn (array $r): string => (string) ($r['event'] ?? ''), $rows);

        self::assertContains('tarpit_stream', $events, 'polluter hits log event=tarpit_stream');
        foreach ($map as $needle) {
            $found = false;
            foreach ($bodies as $b) {
                if (str_contains($b, $needle) && str_contains($b, 'llm_nav=1')) {
                    $found = true;
                    break;
                }
            }
            self::assertTrue($found, "telemetry carries {$needle} with llm_nav=1");
        }
    }
}
