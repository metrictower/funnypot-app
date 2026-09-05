<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Http\HoneypotController;
use Funnypot\App\Llm\LlmClient;
use Funnypot\App\Llm\LlmFakeResponder;
use Funnypot\App\Llm\LlmOutputSanitizer;
use Funnypot\App\Llm\LlmResponseProfiles;
use Funnypot\App\Llm\ProbeClassifier;
use Funnypot\App\Llm\ProbeGate;
use Funnypot\App\Llm\VelocityTracker;
use Funnypot\App\Storage\LlmFakeCache;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\ThreatIntel\AttackClassifier;
use Funnypot\Core\RequestContext;
use Funnypot\Tests\App\Identity\IdentityTestSupport;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

/**
 * The main hit row's `served` flag must reflect what actually went out. It is written AFTER the serve
 * branch so an LLM fake or a decoy archive is logged as served, not as the unserved miss the engine's
 * own answer alone would suggest. The per-IP velocity window counts only unserved, unmatched rows, so
 * a wrong flag here would make a human following our decoy links look like a dirbuster and get pinned.
 */
final class HoneypotControllerServedFlagTest extends TestCase
{
    private const GOOD_HTML =
        '<!doctype html><html><head><title>Sign in</title></head><body><h1>Sign in</h1>'
        . '<form method="post" action="/x"><input name="user"><input name="pass" type="password">'
        . '<button>Log in</button></form></body></html>';

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
            foreach (['', '-wal', '-shm', '.sqlite', '.sqlite-wal', '.sqlite-shm', '.csv'] as $s) {
                @unlink($f . $s);
            }
        }
        $this->tmp = [];
    }

    private function tmpPath(string $n): string
    {
        $p = sys_get_temp_dir() . "/fpservedflag_{$n}_" . bin2hex(random_bytes(6));
        $this->tmp[] = $p;

        return $p;
    }

    /** A controller whose LLM tier answers direct-kind paths with $llmStatus from the sidecar (no renderer). */
    private function controller(SqliteHitStore $store, int $llmStatus): HoneypotController
    {
        $config = AppConfig::fromEnv($this->tmpPath('base'));
        $geo = new \Geo($this->tmpPath('geo') . '.csv');
        $llmFakes = new LlmFakeResponder(
            new ProbeGate(new ProbeClassifier(), new VelocityTracker(), $store),
            new LlmFakeCache($this->tmpPath('cache') . '.sqlite'),
            new LlmClient('http://sidecar/completion', 1500, 320, null, static fn (): array => [
                'status' => $llmStatus,
                'body' => (string) json_encode(['content' => self::GOOD_HTML]),
            ]),
            new LlmOutputSanitizer(),
            $store,
            new LlmResponseProfiles('nginx', 'root ::= "<"', 'root ::= "{"'),
            'v1',
            4,
        );

        return new HoneypotController(
            $store,
            $geo,
            $config,
            dirname(__DIR__, 3) . '/demo/decoys',
            IdentityTestSupport::coreConfigFactory(),
            null,
            null,
            null,
            $llmFakes,
            new AttackClassifier(),
        );
    }

    /** @return array<int,array<string,mixed>> logged rows for $path, in append order */
    private function handle(HoneypotController $c, SqliteHitStore $store, string $path): array
    {
        // @ suppresses the header()/http_response_code() "headers already sent" notices under PHPUnit.
        ob_start();
        @$c->handle(new RequestContext('GET', $path, '', ['User-Agent' => 'curl/8.0']), '9.9.9.9', 'off');
        ob_end_clean();

        return array_values(array_filter(
            $store->delta(0)['rows'],
            static fn (array $r): bool => ($r['path'] ?? '') === $path
        ));
    }

    /** The controller's own row (not a self-logging tier's event row). */
    private static function mainRow(array $rows): array
    {
        $main = array_values(array_filter($rows, static fn (array $r): bool => !in_array($r['event'] ?? '', ['llm-fake', 'panel', 'decoy-archive'], true)));
        self::assertCount(1, $main, 'exactly one main row per request');

        return $main[0];
    }

    public function test_llm_served_path_logs_the_main_row_as_served(): void
    {
        $store = new SqliteHitStore($this->tmpPath('hits') . '.sqlite');
        $rows = $this->handle($this->controller($store, 200), $store, '/super-rare-app/login.asp');

        $events = array_column($rows, 'event');
        self::assertContains('llm-fake', $events, 'the responder logged its own served row');
        self::assertTrue(self::mainRow($rows)['served'], 'the main row must say the LLM fake was served');
        self::assertFalse(self::mainRow($rows)['matched'], 'served is the outcome flag; matched stays the engine verdict');
        // And so the follow accrues no velocity: nothing for this IP is an unserved miss.
        self::assertSame(['recent' => 0, 'extended' => 0], $store->probeVelocity('9.9.9.9'));
    }

    public function test_llm_declined_path_logs_the_main_row_as_unserved(): void
    {
        $store = new SqliteHitStore($this->tmpPath('hits') . '.sqlite');
        $rows = $this->handle($this->controller($store, 500), $store, '/super-rare-app/login.asp');

        self::assertNotContains('llm-fake', array_column($rows, 'event'));
        self::assertFalse(self::mainRow($rows)['served']);
        self::assertSame(['recent' => 1, 'extended' => 1], $store->probeVelocity('9.9.9.9'));
    }

    public function test_probe_path_logs_the_main_row_as_unserved(): void
    {
        $store = new SqliteHitStore($this->tmpPath('hits') . '.sqlite');
        $rows = $this->handle($this->controller($store, 200), $store, '/random9271.php');

        self::assertCount(1, $rows);
        self::assertFalse($rows[0]['served']);
        self::assertSame(['recent' => 1, 'extended' => 1], $store->probeVelocity('9.9.9.9'));
    }

    public function test_decoy_archive_logs_its_event_row_and_the_main_row_as_served(): void
    {
        $store = new SqliteHitStore($this->tmpPath('hits') . '.sqlite');
        $rows = $this->handle($this->controller($store, 200), $store, '/old/site-export.zip');

        $decoy = array_values(array_filter($rows, static fn (array $r): bool => ($r['event'] ?? '') === 'decoy-archive'));
        self::assertCount(1, $decoy, 'the archive handler logged its own row');
        self::assertTrue($decoy[0]['served']);
        self::assertTrue($decoy[0]['matched']);
        self::assertTrue(self::mainRow($rows)['served']);
        self::assertSame(['recent' => 0, 'extended' => 0], $store->probeVelocity('9.9.9.9'));
    }
}
