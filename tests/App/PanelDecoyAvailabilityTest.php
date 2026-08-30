<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Http\HoneypotController;
use Funnypot\App\Llm\LlmClient;
use Funnypot\App\Llm\LlmFakeResponder;
use Funnypot\App\Llm\LlmOutputSanitizer;
use Funnypot\App\Llm\LlmResponseProfiles;
use Funnypot\App\Llm\ProbeClassifier;
use Funnypot\App\Llm\ProbeGate;
use Funnypot\App\Llm\VelocityTracker;
use Funnypot\App\Render\PageShellRenderer;
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
 * Availability guard for the whole HTTP deception surface. A Config/wiring regression (an unknown
 * named Config arg, a bad service construction) makes the engine throw or match nothing, so EVERY
 * decoy/panel/attack path collapses to the plain 404 while only static routes survive — the
 * deception runs dark and looks like an ordinary quiet server. This test drives the real
 * HoneypotController::handle() for a representative slice of that surface and asserts each is served
 * (non-404), so such a regression fails in the suite before it can deploy.
 *
 * The signal is HTTP-level, not body-specific: a served fake never carries the honeypot's own plain
 * 404 footer, and a Config-construction fatal propagates out of handle() (which has no fault
 * containment of its own — only the front controller does) and errors the case. Both are the exact
 * shape the dark-404 incident took.
 */
final class PanelDecoyAvailabilityTest extends TestCase
{
    /** The distinctive footer of HoneypotController's plain fall-through 404. Its presence == dark. */
    private const PLAIN_404_MARKER = '<hr><center>nginx</center>';

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
        $p = sys_get_temp_dir() . "/fpavail_{$n}_" . bin2hex(random_bytes(6));
        $this->tmp[] = $p;

        return $p;
    }

    /**
     * Representative decoy / panel / attack paths, both slash variants where the mount takes one. This
     * IS the covered set — a dark-404 regression turns every row here red at once, which is the point.
     *
     * @return array<string,array{0:string,1:string,2:string}>
     */
    public static function deceptionPaths(): array
    {
        return [
            'dotfile /.env'            => ['GET', '/.env', ''],
            'vcs /.git/config'         => ['GET', '/.git/config', ''],
            'php /phpinfo.php'         => ['GET', '/phpinfo.php', ''],
            'panel /phpmyadmin (bare)' => ['GET', '/phpmyadmin', ''],
            'panel /phpmyadmin/'       => ['GET', '/phpmyadmin/', ''],
            'panel /admin (bare)'      => ['GET', '/admin', ''],
            'panel /admin/'            => ['GET', '/admin/', ''],
            'panel /grafana/login'     => ['GET', '/grafana/login', ''],
            'wp /wp-login.php'         => ['GET', '/wp-login.php', ''],
            'lfi /index.php?page=..'   => ['GET', '/index.php', 'page=../../../../etc/passwd'],
        ];
    }

    /**
     * @dataProvider deceptionPaths
     */
    public function test_path_is_served_not_dark_404(string $method, string $path, string $query): void
    {
        $store = new SqliteHitStore($this->tmpPath('hits') . '.sqlite');
        $controller = $this->controller($store);

        // @ suppresses the http_response_code()/header() "headers already sent" notices — PHPUnit's
        // printer has already written to stdout, so ResponseEmitter cannot really set headers under
        // test. The echoed body is still captured, which is the signal we assert on. A Config fatal
        // would throw straight through this and error the case (handle() has no fault containment).
        ob_start();
        @$controller->handle(
            new RequestContext($method, $path, $query, ['User-Agent' => 'curl/8.0']),
            '9.9.9.9',
            'off'
        );
        $body = (string) ob_get_clean();

        $where = $method . ' ' . $path . ($query !== '' ? '?' . $query : '');
        self::assertNotSame('', $body, "$where returned an empty body — the deception is not serving");
        self::assertStringNotContainsString(
            self::PLAIN_404_MARKER,
            $body,
            "$where fell through to the plain 404 — the deception is dark for this path"
        );

        // Store-level corroboration: the request was logged as served (engine/panel fake) or handled
        // by a self-logging tier (panel / decoy-archive). A plain-404 fall-through logs served=false
        // with no such event, so this catches a dark-404 that somehow still emitted a body.
        $rows = array_values(array_filter(
            $store->delta(0)['rows'],
            static fn (array $r): bool => ($r['path'] ?? '') === $path
        ));
        self::assertNotEmpty($rows, "$where was not logged at all");
        $servedRow = array_values(array_filter($rows, static function (array $r): bool {
            return ($r['served'] ?? false) === true
                || in_array($r['event'] ?? '', ['panel', 'decoy-archive'], true);
        }));
        self::assertNotEmpty($servedRow, "$where was logged but never served (dark-404)");
    }

    /**
     * Mirrors the production wiring closely enough to exercise the engine + panel precedence: the
     * WordPress/phpMyAdmin/Grafana skins are more specific, AdminLTE is the /admin fallback, and the
     * LLM client is stubbed so no network is touched (hermetic). attackEmulation is on by default in
     * AppConfig::fromEnv, so the attack-tier panels (/phpmyadmin) and the LFI probe are served here.
     */
    private function controller(SqliteHitStore $store): HoneypotController
    {
        $config = AppConfig::fromEnv($this->tmpPath('base'));
        $geo = new \Geo($this->tmpPath('geo') . '.csv');
        $decoys = dirname(__DIR__, 2) . '/demo/decoys';

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
            null,
            null,
            null,
            $llmFakes,
            new AttackClassifier(),
        );
    }
}
