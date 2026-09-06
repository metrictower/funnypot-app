<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Http\HoneypotController;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\ThreatIntel\AttackClassifier;
use Funnypot\App\ThreatIntel\ScannerAttributor;
use Funnypot\Core\RequestContext;
use Funnypot\Tests\App\Identity\IdentityTestSupport;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

/**
 * Scanner attribution is ADVISORY: it names the tool on the log row only, after the response has gone
 * out, and must never change a served byte. These tests run the SAME probe through handle() with the
 * attributor on vs off (null) and assert the emitted bytes are identical while only the `tool` column
 * differs — and that the matched needle / tool label never appears in the response.
 */
final class ScannerAttributionControllerTest extends TestCase
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
            foreach (['', '-wal', '-shm', '.sqlite', '.sqlite-wal', '.sqlite-shm', '.csv'] as $s) {
                @unlink($f . $s);
            }
        }
        $this->tmp = [];
    }

    private function tmpPath(string $n): string
    {
        $p = sys_get_temp_dir() . "/fpattrib_{$n}_" . bin2hex(random_bytes(6));
        $this->tmp[] = $p;

        return $p;
    }

    private function controller(SqliteHitStore $store, bool $withAttributor): HoneypotController
    {
        $config = AppConfig::fromEnv($this->tmpPath('base'));
        $geo = new \Geo($this->tmpPath('geo') . '.csv');

        return new HoneypotController(
            $store,
            $geo,
            $config,
            dirname(__DIR__, 3) . '/demo/decoys',
            IdentityTestSupport::coreConfigFactory(),
            null,
            null,
            null,
            null,
            new AttackClassifier(),
            null,
            null,
            $withAttributor ? new ScannerAttributor() : null,
        );
    }

    /** @return array{body:string,rows:array<int,array<string,mixed>>} */
    private function exercise(bool $withAttributor, RequestContext $ctx, string $path): array
    {
        $store = new SqliteHitStore($this->tmpPath('hits') . '.sqlite');
        ob_start();
        @$this->controller($store, $withAttributor)->handle($ctx, '9.9.9.9', 'off');
        $body = (string) ob_get_clean();
        $rows = array_values(array_filter(
            $store->delta(0)['rows'],
            static fn (array $r): bool => ($r['path'] ?? '') === $path
        ));

        return ['body' => $body, 'rows' => $rows];
    }

    public function test_attribution_does_not_change_the_served_bytes(): void
    {
        // A sqlmap-UA probe of an unmapped path: a plain believable 404 either way.
        $path = '/random-unmapped-97213.php';
        $ctx = new RequestContext('GET', $path, '', ['User-Agent' => 'sqlmap/1.8.3#stable']);

        $off = $this->exercise(false, $ctx, $path);
        $on = $this->exercise(true, $ctx, $path);

        self::assertSame($off['body'], $on['body'], 'the served response must be byte-identical with attribution on vs off');
        self::assertStringNotContainsStringIgnoringCase('sqlmap', $on['body'], 'the tool label must never leak into the response');
    }

    public function test_attribution_writes_only_the_tool_column(): void
    {
        $path = '/random-unmapped-55501.php';
        $ctx = new RequestContext('GET', $path, '', ['User-Agent' => 'sqlmap/1.8.3#stable']);

        $off = $this->exercise(false, $ctx, $path);
        $on = $this->exercise(true, $ctx, $path);

        self::assertCount(1, $off['rows']);
        self::assertCount(1, $on['rows']);
        // Off: no tool. On: the bounded tool name, and nothing else changed on the row.
        self::assertSame('', (string) ($off['rows'][0]['tool'] ?? ''));
        self::assertSame('sqlmap', (string) ($on['rows'][0]['tool'] ?? ''));
        // The version is never persisted (no version spliced into tool, ua, or body).
        self::assertStringNotContainsString('1.8.3', (string) ($on['rows'][0]['tool'] ?? ''));
        self::assertSame($off['rows'][0]['ua'], $on['rows'][0]['ua']);
        self::assertSame($off['rows'][0]['body'] ?? null, $on['rows'][0]['body'] ?? null);
    }

    public function test_benign_probe_writes_no_tool(): void
    {
        $path = '/random-unmapped-33320.php';
        $ctx = new RequestContext('GET', $path, 'page=2', ['User-Agent' => 'Mozilla/5.0']);

        $on = $this->exercise(true, $ctx, $path);
        self::assertCount(1, $on['rows']);
        self::assertSame('', (string) ($on['rows'][0]['tool'] ?? ''));
    }
}
