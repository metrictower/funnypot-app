<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Admin\AdminAuth;
use Funnypot\App\Config\AppConfig;
use Funnypot\App\Http\DashboardController;
use Funnypot\App\Storage\SqliteHitStore;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

final class DashboardVncFilterTest extends TestCase
{
    private const PASS = 'operator-secret-pw-vnc';

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
            foreach (['', '-wal', '-shm'] as $suf) {
                @unlink($f . $suf);
            }
        }
        $this->tmp = [];
        unset($_GET, $_POST, $_COOKIE[AdminAuth::COOKIE]);
        $_GET = [];
        $_POST = [];
    }

    private function dbPath(string $tag): string
    {
        $p = sys_get_temp_dir() . '/fp_' . $tag . '_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    private function createHarness(): array
    {
        putenv('FUNNYPOT_ADMIN_PASSWORD=' . self::PASS);
        putenv('FUNNYPOT_PUBLIC_VIEW=full');
        $authPath = $this->dbPath('auth');
        $auth = new AdminAuth($authPath);
        $auth->createOrResetUser('admin', self::PASS);
        $res = $auth->login('admin', self::PASS, '127.0.0.1');
        self::assertTrue($res['ok'] ?? false);

        $hitStore = new SqliteHitStore($this->dbPath('hits'));
        $config = AppConfig::fromEnv(sys_get_temp_dir());

        $controller = new DashboardController(
            $hitStore,
            new \Geo(sys_get_temp_dir() . '/fp-no-geo-' . uniqid()),
            $config,
            sys_get_temp_dir(),
            null,
            null,
            $hitStore,
            $auth,
            null,
        );

        return [$controller, $hitStore];
    }

    public function test_feed_filters_vnc_interactive_and_taunt(): void
    {
        /** @var DashboardController $controller */
        /** @var SqliteHitStore $hitStore */
        [$controller, $hitStore] = $this->createHarness();

        // 3 raw port-scan connects
        for ($i = 1; $i <= 3; $i++) {
            $hitStore->append([
                'ts' => gmdate('c'),
                'ip' => "192.0.2.{$i}",
                'method' => 'VNC',
                'event' => 'connect',
                'path' => "VNC connection from 192.0.2.{$i}:" . (45000 + $i),
            ]);
        }

        // Interactive sessions
        $hitStore->append([
            'ts' => gmdate('c'),
            'ip' => '198.51.100.10',
            'method' => 'VNC',
            'event' => 'handshake_complete',
            'path' => 'VNC handshake complete (800x600, client: RFB 003.008)',
        ]);
        $hitStore->append([
            'ts' => gmdate('c'),
            'ip' => '198.51.100.10',
            'method' => 'VNC',
            'event' => 'screen_viewed',
            'path' => 'VNC framebuffer requested - attacker saw the screen',
        ]);
        $hitStore->append([
            'ts' => gmdate('c'),
            'ip' => '198.51.100.10',
            'method' => 'VNC',
            'event' => 'click',
            'path' => 'VNC mouse click: btn=1 at (150, 250)',
        ]);
        $hitStore->append([
            'ts' => gmdate('c'),
            'ip' => '198.51.100.10',
            'method' => 'VNC',
            'event' => 'popup_shown',
            'path' => 'Reverse-VNC-connection dialog shown by click btn=1 at (150, 250)',
        ]);
        $hitStore->append([
            'ts' => gmdate('c'),
            'ip' => '198.51.100.10',
            'method' => 'VNC',
            'event' => 'trap_triggered',
            'path' => 'Taunt slideshow started',
        ]);
        $hitStore->append([
            'ts' => gmdate('c'),
            'ip' => '198.51.100.10',
            'method' => 'VNC',
            'event' => 'taunt_disconnect',
            'path' => 'VNC taunt slideshow finished - dropping connection',
        ]);

        // 1. All VNC hits: returns all 9
        $_GET = ['feed' => '1', 'after' => '0', 'method' => 'VNC'];
        ob_start();
        $controller->feed();
        $rawAll = (string) ob_get_clean();
        $jsonAll = json_decode($rawAll, true);
        self::assertIsArray($jsonAll);
        self::assertCount(9, $jsonAll['rows']);

        // 2. Interactive VNC: returns 6 (excludes raw connect)
        $_GET = ['feed' => '1', 'after' => '0', 'method' => 'VNC', 'interactive' => '1'];
        ob_start();
        $controller->feed();
        $rawInteractive = (string) ob_get_clean();
        $jsonInteractive = json_decode($rawInteractive, true);
        self::assertIsArray($jsonInteractive);
        self::assertCount(6, $jsonInteractive['rows']);
        foreach ($jsonInteractive['rows'] as $r) {
            self::assertNotSame('connect', $r['event']);
            self::assertSame('VNC', $r['method']);
        }

        // 3. VNC taunts: returns 3 (popup_shown, trap_triggered, taunt_disconnect)
        $_GET = ['feed' => '1', 'after' => '0', 'method' => 'VNC', 'taunt' => '1'];
        ob_start();
        $controller->feed();
        $rawTaunts = (string) ob_get_clean();
        $jsonTaunts = json_decode($rawTaunts, true);
        self::assertIsArray($jsonTaunts);
        self::assertCount(3, $jsonTaunts['rows']);
        $tauntEvents = array_column($jsonTaunts['rows'], 'event');
        self::assertEqualsCanonicalizing(['popup_shown', 'trap_triggered', 'taunt_disconnect'], $tauntEvents);
    }

    public function test_shell_renders_vnc_quick_view_buttons(): void
    {
        /** @var DashboardController $controller */
        [$controller] = $this->createHarness();

        ob_start();
        $controller->shell();
        $html = (string) ob_get_clean();

        // Check button markup
        self::assertStringContainsString("data-f='{\"method\":\"VNC\"}'>VNC</button>", $html);
        self::assertStringContainsString("data-f='{\"method\":\"VNC\",\"interactive\":\"1\"}'", $html);
        self::assertStringContainsString('>VNC interactive</button>', $html);
        self::assertStringContainsString("data-f='{\"method\":\"VNC\",\"taunt\":\"1\"}'", $html);
        self::assertStringContainsString('>VNC taunts</button>', $html);

        // Verify JSON in data-f attributes can be decoded cleanly
        preg_match_all('/class=[\'"][^\'"]*qv[^\'"]*[\'"]\s+data-f=[\'"]([^\'"]+)[\'"]/', $html, $matches);
        self::assertNotEmpty($matches[1]);
        foreach ($matches[1] as $rawJson) {
            $decoded = json_decode(html_entity_decode($rawJson, ENT_QUOTES), true);
            self::assertIsArray($decoded, "Invalid JSON in data-f: {$rawJson}");
        }
    }
}
