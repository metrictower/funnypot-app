<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Http\HoneypotController;
use Funnypot\Tests\App\Identity\IdentityTestSupport;
use Funnypot\App\Http\SleepDecoy;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\Storage\TarpitBudget;
use Funnypot\App\ThreatIntel\AttackClassifier;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

/**
 * FP-0228 SHOULD-FIX 1 — the controller-level proof that a SERVED SQLi SLEEP probe is ACTUALLY delayed.
 *
 * The plan review caught that the controller computes its attack class ($payloadClass) ONLY on the 404
 * fall-through, so it is null on the served-attack-fake path — meaning a recognised SQLi SLEEP probe
 * that the engine SERVES a fake for would, if the decoy were gated on that value, get NO delay (the
 * ticket's own acceptance would fail). The prior unit test could not catch this: it called
 * SleepDecoy::maybeDelay() directly, bypassing the controller wiring entirely.
 *
 * This drives the REAL {@see HoneypotController::handle()} end-to-end (the engine serves the fake) with
 * an injected spy sleeper, and proves the honoured delay is applied on that SERVED path — because the
 * decoy classifies the sleep structure INDEPENDENTLY, not from the null-on-served $payloadClass.
 */
final class SleepDecoyControllerTest extends TestCase
{
    /** @var string[] */
    private array $tmp = [];
    /** @var array<string,string|false> */
    private array $savedEnv = [];

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
        $this->savedEnv['FUNNYPOT_SLEEP_DECOY'] = getenv('FUNNYPOT_SLEEP_DECOY');
        $this->savedEnv['FUNNYPOT_SLEEP_PER_REQ_CAP_MS'] = getenv('FUNNYPOT_SLEEP_PER_REQ_CAP_MS');
    }

    protected function tearDown(): void
    {
        foreach ($this->savedEnv as $k => $v) {
            $v === false ? putenv($k) : putenv("$k=$v");
        }
        foreach ($this->tmp as $f) {
            foreach (['', '-wal', '-shm', '.sqlite', '.sqlite-wal', '.sqlite-shm'] as $s) {
                @unlink($f . $s);
            }
        }
        $this->tmp = [];
    }

    private function tmpPath(string $n): string
    {
        $p = sys_get_temp_dir() . "/fp_sleepctl_{$n}_" . bin2hex(random_bytes(6));
        $this->tmp[] = $p;

        return $p;
    }

    /**
     * @param array<int> $sleeps out-param the spy sleeper appends to
     * @return array{0:HoneypotController,1:SqliteHitStore}
     */
    private function controller(array &$sleeps, bool $decoyOn = true): array
    {
        putenv('FUNNYPOT_SLEEP_DECOY=' . ($decoyOn ? '1' : '0'));
        putenv('FUNNYPOT_SLEEP_PER_REQ_CAP_MS=2000');
        $config = AppConfig::fromEnv($this->tmpPath('base'));
        $store = new SqliteHitStore($this->tmpPath('hits') . '.sqlite');
        $geo = new \Geo($this->tmpPath('geo') . '.csv');
        $decoys = dirname(__DIR__, 2) . '/demo/decoys';

        $sleeper = static function (int $ms) use (&$sleeps): void {
            $sleeps[] = $ms; // spy — no real sleep, so the test is deterministic and fast
        };
        $budget = new TarpitBudget(
            $this->tmpPath('tarpit') . '.sqlite',
            true,
            8,
            4,
            PHP_INT_MAX,
            PHP_INT_MAX,
            PHP_INT_MAX,
            PHP_INT_MAX,
            15,
            static fn (): int => 1_000_000,
            0,
            $sleeper
        );
        // Jitter = its ceiling ⇒ a capped 2 s probe reaches exactly 2000 ms (deterministic assertion).
        $decoy = $decoyOn ? new SleepDecoy($budget, $config, new AttackClassifier(), static fn (int $c): int => $c) : null;

        $controller = new HoneypotController(
            $store,
            $geo,
            $config,
            $decoys,
            IdentityTestSupport::coreConfigFactory(),
            null,
            null,
            null,
            null,                      // no LLM responder — the engine serves the SQLi fake on its own
            new AttackClassifier(),
            null,
            $decoy
        );

        return [$controller, $store];
    }

    /** @return array<int,array<string,mixed>> */
    private function rowsFor(SqliteHitStore $store, string $path): array
    {
        return array_values(array_filter(
            $store->delta(0)['rows'],
            static fn (array $r): bool => ($r['path'] ?? '') === $path
        ));
    }

    public function test_a_served_sqli_sleep_probe_is_actually_delayed(): void
    {
        $sleeps = [];
        [$c, $store] = $this->controller($sleeps);

        // A calibrated SLEEP(2) SQLi probe on a normal path: the engine RECOGNISES it and SERVES an attack
        // fake ($response !== null) — the exact path where the controller's $payloadClass is null.
        ob_start();
        @$c->handle(new RequestContext('GET', '/products.php', 'id=1 AND SLEEP(2)', ['User-Agent' => 'sqlmap/1.7'], null), '9.9.9.9', 'off');
        $body = ob_get_clean();

        // The row proves the engine went down the SERVED path (not the 404 fall-through).
        $rows = $this->rowsFor($store, '/products.php');
        self::assertNotEmpty($rows, 'the probe was logged');
        self::assertTrue((bool) ($rows[0]['served'] ?? false), 'the engine SERVED a fake (the null-$payloadClass path)');

        // The honoured delay was applied on that served path — SHOULD-FIX 1.
        self::assertSame([2000], $sleeps, 'a SERVED SQLi SLEEP(2) probe is delayed 2000 ms via the controller');
        self::assertNotSame('', $body, 'a fake response is still emitted (the delay is additive, not a replacement)');
    }

    public function test_a_benign_request_through_the_controller_is_never_delayed(): void
    {
        $sleeps = [];
        [$c] = $this->controller($sleeps);

        ob_start();
        @$c->handle(new RequestContext('GET', '/index.php', 'id=42&name=bob', ['User-Agent' => 'curl/8.0'], null), '9.9.9.8', 'off');
        ob_get_clean();

        self::assertSame([], $sleeps, 'a benign request carries no sleep structure and is never delayed');
    }

    public function test_off_by_default_controller_adds_no_delay(): void
    {
        $sleeps = [];
        [$c, $store] = $this->controller($sleeps, false); // decoy null (off)

        ob_start();
        @$c->handle(new RequestContext('GET', '/products.php', 'id=1 AND SLEEP(2)', ['User-Agent' => 'sqlmap/1.7'], null), '9.9.9.7', 'off');
        ob_get_clean();

        self::assertSame([], $sleeps, 'with the decoy off (null), even a served SQLi SLEEP probe is not delayed');
        // and it is still served + logged normally (feature-off changes nothing but the timing).
        self::assertNotEmpty($this->rowsFor($store, '/products.php'));
    }
}
