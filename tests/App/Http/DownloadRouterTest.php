<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\AiApi\StreamEmitter;
use Funnypot\App\Http\DownloadRouter;
use Funnypot\App\Render\Fake\Fleet;
use Funnypot\App\Storage\HitStore;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;

/**
 * The endless backup-download bait seam: which paths it owns, that the manifest is a plausible seeded
 * file list echoing the throttle config, that every trigger logs event=download intel, and that the
 * non-JS fallback stays under its byte cap, emits a valid zip local header, and never 500s.
 */
final class DownloadRouterTest extends TestCase
{
    private const SEED = 4242;

    private DlHitSpy $hits;
    private string $host = '';

    protected function setUp(): void
    {
        $this->hits = new DlHitSpy();
        $this->host = (string) Fleet::fromSeed(self::SEED)->servers()[0]['host'];
    }

    private function router(): DownloadRouter
    {
        return new DownloadRouter(
            $this->hits,
            self::SEED,
            "/* sw */",
            100,
            200,
            100,
            50,
            20,
            2 // 2 MiB fallback cap
        );
    }

    public function testMatchesOnlyItsThreePaths(): void
    {
        $r = $this->router();
        $this->assertTrue($r->matches('/__dl/sw.js'));
        $this->assertTrue($r->matches('/__dl/manifest'));
        $this->assertTrue($r->matches('/backup.zip'));
        $this->assertFalse($r->matches('/__dl'));
        $this->assertFalse($r->matches('/backup.zip.bak'));
        $this->assertFalse($r->matches('/'));
    }

    public function testManifestIsSeededAndEchoesThrottle(): void
    {
        $m = $this->router()->manifest($this->host);
        $this->assertNotEmpty($m['files']);
        $this->assertArrayHasKey('path', $m['files'][0]);
        $this->assertArrayHasKey('size', $m['files'][0]);
        $this->assertSame(100, $m['throttle']['chunkMinKb']);
        $this->assertSame(200, $m['throttle']['chunkMaxKb']);
        $this->assertSame(50, $m['throttle']['varyPct']);
        // Deterministic: same host -> identical manifest.
        $this->assertSame($m, $this->router()->manifest($this->host));
    }

    public function testThrottleToleratesMaxBelowMin(): void
    {
        $r = new DownloadRouter($this->hits, self::SEED, '', 200, 50, 100, 50, 20, 2);
        $t = $r->throttleBlock();
        $this->assertGreaterThanOrEqual($t['chunkMinKb'], $t['chunkMaxKb']);
    }

    public function testLocalFileHeaderIsAValidStoreZipHeader(): void
    {
        $h = $this->router()->localFileHeader('var/backups/db.sql');
        $this->assertSame("PK\x03\x04", substr($h, 0, 4));
        // flags byte (offset 6) has bit 3 (data descriptor) set; compression (offset 8) is store (0).
        $this->assertSame(0x08, ord($h[6]));
        $this->assertSame(0x00, ord($h[8]));
        $this->assertStringEndsWith('var/backups/db.sql', $h);
    }

    public function testManifestFetchLogsDownloadIntel(): void
    {
        $out = $this->handle('/__dl/manifest', 'host=' . $this->host, 'GET');
        $dl = array_values(array_filter($this->hits->appended, static fn (array $e): bool => ($e['event'] ?? '') === 'download'));
        $this->assertCount(1, $dl);
        $this->assertStringContainsString('host=', (string) $dl[0]['body']);
        $this->assertJson($out);
    }

    public function testSwScriptServedAsJavascript(): void
    {
        $captured = '';
        $emitter = new StreamEmitter(static function (string $b) use (&$captured): void { $captured .= $b; }, 0);
        $r = new DownloadRouter($this->hits, self::SEED, "/* the worker */", 100, 200, 100, 50, 20, 2, static fn (): StreamEmitter => $emitter);
        $r->handle(new RequestContext('GET', '/__dl/sw.js'), '203.0.113.5');
        $this->assertStringContainsString('the worker', $captured);
        $this->assertSame('application/javascript; charset=utf-8', $emitter->headers()['Content-Type'] ?? '');
        $this->assertSame('/', $emitter->headers()['Service-Worker-Allowed'] ?? '');
    }

    public function testFallbackStaysUnderCapAndStartsWithZipHeader(): void
    {
        $out = $this->handle('/backup.zip', 'host=' . $this->host, 'GET');
        $this->assertSame("PK\x03\x04", substr($out, 0, 4));
        $this->assertLessThanOrEqual(2 * 1024 * 1024, strlen($out)); // <= cap
        $this->assertGreaterThan(1024 * 1024, strlen($out));         // and it actually streamed a lot
        // fallback also counts as a bait signal
        $dl = array_filter($this->hits->appended, static fn (array $e): bool => ($e['event'] ?? '') === 'download');
        $this->assertCount(1, $dl);
    }

    public function testEasedDelayBreathesWithinBounds(): void
    {
        $r = $this->router();
        for ($n = 0; $n < 40; $n++) {
            $d = $r->easedDelayMs($n);
            $this->assertGreaterThanOrEqual((int) round(100 * 0.2), $d);
            $this->assertLessThanOrEqual((int) round(100 * 5), $d);
        }
    }

    public function testUnknownHostStillProducesAManifestAndNeverFaults(): void
    {
        $out = $this->handle('/__dl/manifest', 'host=no-such-host', 'GET');
        $this->assertJson($out);
        $this->assertStringNotContainsString('Fatal', $out);
        $m = json_decode($out, true);
        $this->assertNotEmpty($m['files']);
    }

    private function handle(string $path, string $query, string $method): string
    {
        $captured = '';
        $factory = static function () use (&$captured): StreamEmitter {
            return new StreamEmitter(static function (string $b) use (&$captured): void { $captured .= $b; }, 0);
        };
        $r = new DownloadRouter(
            $this->hits, self::SEED, "/* sw */", 100, 200, 100, 50, 20, 2, $factory
        );
        $r->handle(new RequestContext($method, $path, $query), '203.0.113.7');

        return $captured;
    }
}

/** Minimal HitStore recording appends; every other method inert. */
final class DlHitSpy implements HitStore
{
    /** @var array<int,array<string,mixed>> */
    public array $appended = [];

    public function append(array $entry): void
    {
        $this->appended[] = $entry;
    }

    public function delta(int $cursor, array $filters = []): array
    {
        return ['cursor' => 0, 'reset' => false, 'rows' => []];
    }

    public function older(int $skip, array $filters = []): array
    {
        return ['rows' => [], 'more' => false];
    }

    public function stats(): array
    {
        return [];
    }

    public function widgets(): array
    {
        return [];
    }

    public function prune(int $keep): void
    {
    }

    public function clear(): void
    {
    }

    public function import(): int
    {
        return 0;
    }

    public function probeVelocity(string $ip): array
    {
        return ['recent' => 0, 'extended' => 0];
    }

    public function flagBulkScan(string $ip, int $hours): void
    {
    }

    public function isBulkFlagged(string $ip): bool
    {
        return false;
    }
}
