<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Http\HoneypotController;
use Funnypot\Core\Config;
use Funnypot\Core\Detection;
use Funnypot\Core\FakeHandle;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SynthesizedResponse;
use PHPUnit\Framework\TestCase;

/**
 * FP-0003: the prod-impossible X-Pot-Served debug header. The phpunit CLI SAPI cannot introspect header()
 * (see LoginFormOracleTest), so the header VALUE is computed by the pure HoneypotController::debugServedValue()
 * and asserted directly — including end-to-end against the real engine's served-by handle. The flag is
 * default-off (prod is default-deny: deploy.sh never sets FUNNYPOT_DEBUG_HEADERS) and the `X-Pot-` namespace
 * is disjoint from the load-bearing `X-Detected-*` / `X-Request-Id` namespaces.
 */
final class DebugHeaderTest extends TestCase
{
    private function engine(): Honeypot
    {
        $cfg = new Config('respond', static fn (RequestContext $r): bool => true, 'matched-only',
            static fn (RequestContext $r): string => 'x', 'coherent', Style::REALISTIC, 'critical', 65536, 0, 0, false);
        $cfg->attackEmulation = true;

        return Honeypot::default($cfg);
    }

    /** Acceptance: flag-on ⇒ X-Pot-Served == `<tier>/<id>` for a known probe (phpMyAdmin gate). */
    public function test_value_from_real_phpmyadmin_probe(): void
    {
        $r = $this->engine()->respond(new RequestContext('GET', '/phpmyadmin/', '', [], null, 'x.test'));
        self::assertNotNull($r, 'the phpMyAdmin gate probe must serve a fake');
        self::assertSame('attack/attack-phpmyadmin-gate', HoneypotController::debugServedValue($r));
    }

    public function test_value_for_attack_and_route_handles(): void
    {
        self::assertSame('attack/attack-xyz', self::valueFor(FakeHandle::attack('attack-xyz')));
        self::assertSame('route/some-route-key', self::valueFor(FakeHandle::route('some-route-key')));
    }

    public function test_null_handle_yields_null(): void
    {
        // An app-generated panel/LLM fake carries no served-by handle, so the header is never stamped.
        $resp = new SynthesizedResponse(200, [], 'x', Detection::none());
        self::assertNull(HoneypotController::debugServedValue($resp), 'no handle ⇒ no debug value');
    }

    public function test_flag_is_default_off(): void
    {
        self::withEnv(null, function (): void {
            self::assertFalse(AppConfig::fromEnv(sys_get_temp_dir())->debugHeaders, 'unset ⇒ off (opt-in, prod-safe)');
        });
        self::withEnv('0', function (): void {
            self::assertFalse(AppConfig::fromEnv(sys_get_temp_dir())->debugHeaders, "'0' ⇒ off");
        });
    }

    public function test_flag_on_via_env(): void
    {
        foreach (['1', 'on', 'true', 'yes', 'YES'] as $on) {
            self::withEnv($on, function () use ($on): void {
                self::assertTrue(AppConfig::fromEnv(sys_get_temp_dir())->debugHeaders, "'{$on}' ⇒ on");
            });
        }
    }

    /** CI acceptance: `X-Pot-` must never appear in the engine's compiled artifacts (not a served byte). */
    public function test_x_pot_absent_from_compiled_artifacts(): void
    {
        $compiled = dirname(__DIR__, 3) . '/vendor/metrictower/funnypot-core/resources/compiled';
        if (!is_dir($compiled)) {
            self::markTestSkipped('compiled core artifacts not present');
        }
        foreach (glob($compiled . '/*.php') ?: [] as $f) {
            self::assertStringNotContainsString('X-Pot-', (string) file_get_contents($f), basename($f) . ' must not carry X-Pot-');
        }
    }

    /** CI acceptance: the X-Pot- header is EMITTED from exactly one place — HoneypotController's debug-gated stamp. */
    public function test_x_pot_emitted_only_from_controller(): void
    {
        $src = dirname(__DIR__, 3) . '/src';
        $hits = [];
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($src, \FilesystemIterator::SKIP_DOTS));
        foreach ($it as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }
            // The emission, not a doc mention: a header() call that writes an X-Pot- header.
            if (preg_match("/header\\(\\s*'X-Pot-/", (string) file_get_contents($file->getPathname())) === 1) {
                $hits[] = $file->getFilename();
            }
        }
        self::assertSame(['HoneypotController.php'], array_values(array_unique($hits)), 'X-Pot- must be emitted only from HoneypotController');

        // ...and that emission is inside the debugHeaders-gated stampDebugHeader(), nowhere ungated.
        $controller = (string) file_get_contents($src . '/App/Http/HoneypotController.php');
        $stamp = strstr($controller, 'function stampDebugHeader');
        self::assertIsString($stamp);
        self::assertStringContainsString("header('X-Pot-Served: '", (string) $stamp, 'the emission lives in the gated stamp method');
    }

    private static function valueFor(FakeHandle $handle): ?string
    {
        $resp = new SynthesizedResponse(200, [], 'x', Detection::none());
        $resp->servedBy = $handle;

        return HoneypotController::debugServedValue($resp);
    }

    private static function withEnv(?string $value, callable $fn): void
    {
        $prev = getenv('FUNNYPOT_DEBUG_HEADERS');
        if ($value === null) {
            putenv('FUNNYPOT_DEBUG_HEADERS');
        } else {
            putenv('FUNNYPOT_DEBUG_HEADERS=' . $value);
        }
        try {
            $fn();
        } finally {
            if ($prev === false) {
                putenv('FUNNYPOT_DEBUG_HEADERS');
            } else {
                putenv('FUNNYPOT_DEBUG_HEADERS=' . $prev);
            }
        }
    }
}
