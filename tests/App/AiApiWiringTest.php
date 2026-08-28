<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\AiApi\AiApiRouter;
use Funnypot\App\AiApi\AiChatHandler;
use Funnypot\App\Config\AppConfig;
use Funnypot\App\Http\CorporateController;
use Funnypot\App\Http\DashboardController;
use Funnypot\App\Http\HomeController;
use Funnypot\App\Http\HoneypotController;
use Funnypot\App\Http\Router;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 2) . '/demo/lib/geo.php';

/**
 * The front-controller wiring: a POST chat path is intercepted by the AiApiRouter before the honeypot
 * catch-all, while a non-chat POST falls through to the honeypot. Proven by side effect — the honeypot
 * appends a hit row; the AI spy does not — so a row appearing (or not) tells which arm handled it.
 */
final class AiApiWiringTest extends TestCase
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
            foreach (['', '-wal', '-shm', '.sqlite', '.sqlite-wal', '.sqlite-shm'] as $s) {
                @unlink($f . $s);
            }
        }
        $this->tmp = [];
        putenv('FUNNYPOT_AI_API');
        putenv('FUNNYPOT_AI_STRICT_AUTH');
        putenv('FUNNYPOT_AI_STRICT_MODEL');
    }

    private function tmpPath(string $n): string
    {
        $p = sys_get_temp_dir() . "/fpwire_{$n}_" . bin2hex(random_bytes(6));
        $this->tmp[] = $p;

        return $p;
    }

    public function test_post_chat_path_is_routed_to_the_ai_api_not_the_honeypot(): void
    {
        $store = new SqliteHitStore($this->tmpPath('hits') . '.sqlite');
        $calls = 0;
        $router = $this->router($store, $this->spyHandler($calls));

        ob_start();
        $router->dispatch(new RequestContext('POST', '/api/chat'), '9.9.9.9', 'off');
        ob_end_clean();

        self::assertSame(1, $calls, 'the AI handler should have served the chat POST');
        self::assertSame([], $store->delta(0)['rows'], 'the honeypot must not have been reached');
    }

    public function test_non_chat_post_falls_through_to_the_honeypot(): void
    {
        $store = new SqliteHitStore($this->tmpPath('hits') . '.sqlite');
        $calls = 0;
        $router = $this->router($store, $this->spyHandler($calls));

        // The honeypot serves a fake, whose ResponseEmitter calls http_response_code(); under phpunit
        // headers are already "sent" (progress output), so suppress that warning. The store append we
        // assert on runs before the emit, so the routing decision is still fully observable.
        ob_start();
        @$router->dispatch(new RequestContext('POST', '/wp-login.php'), '9.9.9.9', 'off');
        ob_end_clean();

        self::assertSame(0, $calls, 'the AI handler must not see a non-chat path');
        $rows = $store->delta(0)['rows'];
        self::assertNotEmpty($rows, 'the honeypot should have logged the probe');
        self::assertSame('/wp-login.php', $rows[count($rows) - 1]['path']);
    }

    public function test_ai_api_flag_reads_from_env(): void
    {
        foreach (['1', 'on', 'true', 'yes', 'ON', 'True'] as $on) {
            putenv('FUNNYPOT_AI_API=' . $on);
            self::assertTrue(AppConfig::fromEnv(sys_get_temp_dir())->aiApiEnabled, "'$on' should enable");
        }
        foreach (['0', 'off', 'no', ''] as $off) {
            putenv('FUNNYPOT_AI_API=' . $off);
            self::assertFalse(AppConfig::fromEnv(sys_get_temp_dir())->aiApiEnabled, "'$off' should disable");
        }
        putenv('FUNNYPOT_AI_API');   // unset
        self::assertFalse(AppConfig::fromEnv(sys_get_temp_dir())->aiApiEnabled, 'unset should disable');
    }

    public function test_strict_auth_and_model_flags_default_off(): void
    {
        putenv('FUNNYPOT_AI_STRICT_AUTH');   // unset
        putenv('FUNNYPOT_AI_STRICT_MODEL');  // unset
        $config = AppConfig::fromEnv(sys_get_temp_dir());
        self::assertFalse($config->aiStrictAuth, 'strict auth is opt-in (open box by default)');
        self::assertFalse($config->aiStrictModel, 'strict model is opt-in (any model by default)');

        putenv('FUNNYPOT_AI_STRICT_AUTH=1');
        putenv('FUNNYPOT_AI_STRICT_MODEL=yes');
        $strict = AppConfig::fromEnv(sys_get_temp_dir());
        self::assertTrue($strict->aiStrictAuth);
        self::assertTrue($strict->aiStrictModel);
        putenv('FUNNYPOT_AI_STRICT_AUTH');
        putenv('FUNNYPOT_AI_STRICT_MODEL');
    }

    /** @param int $calls counter incremented on each serve() */
    private function spyHandler(int &$calls): AiApiRouter
    {
        $handler = $this->getMockBuilder(AiChatHandler::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['serve'])
            ->getMock();
        $handler->method('serve')->willReturnCallback(static function () use (&$calls): void {
            $calls++;
        });

        return new AiApiRouter($handler);
    }

    private function router(SqliteHitStore $store, AiApiRouter $aiApi): Router
    {
        $config = AppConfig::fromEnv($this->tmpPath('base'));
        $geo = new \Geo($this->tmpPath('geo') . '.csv');
        $decoys = dirname(__DIR__, 2) . '/demo/decoys';
        $assets = dirname(__DIR__, 2) . '/demo/assets';

        $honeypot = new HoneypotController($store, $geo, $config, $decoys);
        $dashboard = new DashboardController($store, $geo, $config, $assets);
        $corporate = new CorporateController($store, $geo, $config, $assets);
        $home = new HomeController($store, $geo, $config, $assets);

        return new Router($config, $honeypot, $dashboard, $corporate, $home, $aiApi);
    }
}
