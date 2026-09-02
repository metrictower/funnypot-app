<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Docker\DockerApiResponder;
use Funnypot\App\Docker\DockerApiRouter;
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
 * The front-controller wiring for the Docker decoy: a Docker path (GET recon or POST create/start) is
 * intercepted by the Docker seam before the honeypot catch-all, while a non-Docker path falls through
 * to the honeypot. Proven by side effect — the honeypot appends a hit row; the Docker spy does not.
 */
final class DockerApiWiringTest extends TestCase
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
        putenv('FUNNYPOT_DOCKER_API');
    }

    private function tmpPath(string $n): string
    {
        $p = sys_get_temp_dir() . "/fpdockwire_{$n}_" . bin2hex(random_bytes(6));
        $this->tmp[] = $p;

        return $p;
    }

    public function test_docker_path_is_routed_to_the_decoy_not_the_honeypot(): void
    {
        $store = new SqliteHitStore($this->tmpPath('hits') . '.sqlite');
        $calls = 0;
        $router = $this->router($store, $this->spyDocker($calls));

        ob_start();
        $router->dispatch(new RequestContext('GET', '/v1.24/version'), '9.9.9.9', 'off');
        ob_end_clean();

        self::assertSame(1, $calls, 'the Docker responder should have served the version probe');
        self::assertSame([], $store->delta(0)['rows'], 'the honeypot must not have been reached');
    }

    public function test_docker_create_post_is_routed_to_the_decoy(): void
    {
        $store = new SqliteHitStore($this->tmpPath('hits') . '.sqlite');
        $calls = 0;
        $router = $this->router($store, $this->spyDocker($calls));

        ob_start();
        $router->dispatch(new RequestContext('POST', '/containers/create'), '9.9.9.9', 'off');
        ob_end_clean();

        self::assertSame(1, $calls);
        self::assertSame([], $store->delta(0)['rows']);
    }

    public function test_non_docker_path_falls_through_to_the_honeypot(): void
    {
        $store = new SqliteHitStore($this->tmpPath('hits') . '.sqlite');
        $calls = 0;
        $router = $this->router($store, $this->spyDocker($calls));

        ob_start();
        @$router->dispatch(new RequestContext('GET', '/some/random/path'), '9.9.9.9', 'off');
        ob_end_clean();

        self::assertSame(0, $calls, 'the Docker responder must not see a non-Docker path');
        self::assertNotEmpty($store->delta(0)['rows'], 'the honeypot should have logged the probe');
    }

    public function test_docker_api_flag_reads_from_env(): void
    {
        foreach (['1', 'on', 'true', 'yes', 'ON', 'True'] as $on) {
            putenv('FUNNYPOT_DOCKER_API=' . $on);
            self::assertTrue(AppConfig::fromEnv(sys_get_temp_dir())->dockerApiEnabled, "'$on' should enable");
        }
        foreach (['0', 'off', 'no', ''] as $off) {
            putenv('FUNNYPOT_DOCKER_API=' . $off);
            self::assertFalse(AppConfig::fromEnv(sys_get_temp_dir())->dockerApiEnabled, "'$off' should disable");
        }
        putenv('FUNNYPOT_DOCKER_API');   // unset
        self::assertFalse(AppConfig::fromEnv(sys_get_temp_dir())->dockerApiEnabled, 'unset should disable (opt-in)');
    }

    public function test_bare_version_on_port_80_falls_through_to_the_honeypot(): void
    {
        // FP-0264 port scoping: bare /version is NOT owned on a web port, so it reaches the honeypot.
        $store = new SqliteHitStore($this->tmpPath('hits') . '.sqlite');
        $calls = 0;
        $router = $this->router($store, $this->spyDocker($calls, 80));

        ob_start();
        @$router->dispatch(new RequestContext('GET', '/version'), '9.9.9.9', 'off');
        ob_end_clean();

        self::assertSame(0, $calls, 'the Docker decoy must not claim bare /version on port 80');
        self::assertNotEmpty($store->delta(0)['rows'], 'the honeypot logged the /version probe');
    }

    public function test_bare_version_on_docker_port_is_served_by_the_decoy(): void
    {
        $store = new SqliteHitStore($this->tmpPath('hits') . '.sqlite');
        $calls = 0;
        $router = $this->router($store, $this->spyDocker($calls, 2375));

        ob_start();
        $router->dispatch(new RequestContext('GET', '/version'), '9.9.9.9', 'off');
        ob_end_clean();

        self::assertSame(1, $calls, 'on a Docker port the decoy serves bare /version');
        self::assertSame([], $store->delta(0)['rows']);
    }

    public function test_dashboard_path_still_resolves_on_port_80(): void
    {
        // With the Docker decoy armed on port 80, the operator dashboard path is not shadowed — the
        // Docker seam only claims Docker path shapes there (the whole-port shadow is accepted ONLY on
        // 2375/4243). Proven by the decoy spy seeing 0 calls for the dashboard path.
        $store = new SqliteHitStore($this->tmpPath('hits') . '.sqlite');
        $calls = 0;
        $docker = $this->spyDocker($calls, 80);
        $config = AppConfig::fromEnv($this->tmpPath('base'));
        $fp = rtrim($config->funnypotPath, '/');

        self::assertFalse($docker->matches($fp), 'the dashboard path is not a Docker surface on port 80');
        self::assertTrue($docker->matches('/version') === false, 'sanity: bare version not owned on 80');
    }

    public function test_docker_port_shadows_everything_including_the_dashboard(): void
    {
        // The accepted trade-off: on a Docker port the seam owns the whole port (so an unmatched path
        // is answered as dockerd's page-not-found rather than an nginx HTML 404 tell).
        $calls = 0;
        $docker = $this->spyDocker($calls, 2375);
        $config = AppConfig::fromEnv($this->tmpPath('base'));
        self::assertTrue($docker->matches(rtrim($config->funnypotPath, '/')), 'accepted: Docker port shadows the dashboard');
    }

    /** @param int $calls counter incremented on each respond() */
    private function spyDocker(int &$calls, int $port = 0): DockerApiRouter
    {
        $responder = $this->getMockBuilder(DockerApiResponder::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['respond'])
            ->getMock();
        $responder->method('respond')->willReturnCallback(static function () use (&$calls): void {
            $calls++;
        });

        return new DockerApiRouter($responder, $port);
    }

    private function router(SqliteHitStore $store, DockerApiRouter $docker): Router
    {
        $config = AppConfig::fromEnv($this->tmpPath('base'));
        $geo = new \Geo($this->tmpPath('geo') . '.csv');
        $decoys = dirname(__DIR__, 2) . '/demo/decoys';
        $assets = dirname(__DIR__, 2) . '/demo/assets';

        $honeypot = new HoneypotController($store, $geo, $config, $decoys);
        $dashboard = new DashboardController($store, $geo, $config, $assets);
        $corporate = new CorporateController($store, $geo, $config, $assets);
        $home = new HomeController($store, $geo, $config, $assets);

        return new Router($config, $honeypot, $dashboard, $corporate, $home, null, null, null, $docker);
    }
}
