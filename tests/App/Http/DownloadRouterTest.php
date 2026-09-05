<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\AiApi\StreamEmitter;
use Funnypot\App\Http\BaitEventLimiter;
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
        $this->assertTrue($r->matches('/__dl/backup.zip'));
        $this->assertFalse($r->matches('/__dl'));
        $this->assertFalse($r->matches('/__dl/backup.zip.bak'));
        $this->assertFalse($r->matches('/'));
    }

    /**
     * The bait must never claim the bare /backup.zip. That path is honeypot surface: it serves the
     * nested decoy archive and, decisively, is where the detection engine + classifier queue the
     * AbuseIPDB / Threat Intel report. A seam ahead of the catch-all would silence those reports.
     */
    public function testNeverClaimsTheHoneypotOwnedBackupZip(): void
    {
        $r = $this->router();
        $this->assertFalse($r->matches('/backup.zip'));
        $this->assertStringStartsWith('/__dl/', DownloadRouter::ZIP_PATH);
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
        // ts is stored as TEXT and retention compares it lexicographically, so it must be ISO-8601.
        $this->assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}T/', (string) $dl[0]['ts']);
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

    /**
     * FP-0112: every other case in this file injects the "/* sw *\/" stub, which is exactly how the
     * router-level plumbing test suite kept passing while the REAL src/App/Download/sw.js shipped a
     * self-identifying comment to production for three commits (nothing here ever read the real
     * bytes). This one case wires the actual on-disk file through — the same construction
     * demo/index.php uses in production — and asserts the served body is byte-identical to it, so a
     * change to demo/index.php's wiring (or a future stub creeping into every case again) cannot
     * silently stop this suite from ever touching the real artifact. Fingerprint-safety of the real
     * file's content is FingerprintSafetyTest/ServedSurfacesFingerprintTest's job, not this one's.
     */
    public function testSwPathServesTheRealOnDiskWorkerFileByteIdentical(): void
    {
        $realSw = (string) file_get_contents(dirname(__DIR__, 3) . '/src/App/Download/sw.js');
        $this->assertNotSame('', $realSw, 'src/App/Download/sw.js must exist and be non-empty for this test to mean anything');

        $captured = '';
        $emitter = new StreamEmitter(static function (string $b) use (&$captured): void { $captured .= $b; }, 0);
        $r = new DownloadRouter($this->hits, self::SEED, $realSw, 100, 200, 100, 50, 20, 2, static fn (): StreamEmitter => $emitter);
        $r->handle(new RequestContext('GET', '/__dl/sw.js'), '203.0.113.6');

        $this->assertSame($realSw, $captured, 'the served body must be byte-identical to the real on-disk worker');
        $this->assertSame('application/javascript; charset=utf-8', $emitter->headers()['Content-Type'] ?? '');
        $this->assertSame('/', $emitter->headers()['Service-Worker-Allowed'] ?? '');
    }

    public function testFallbackStaysUnderCapAndStartsWithZipHeader(): void
    {
        $out = $this->handle('/__dl/backup.zip', 'host=' . $this->host, 'GET');
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

    /**
     * The route is gate-exempt, so its telemetry is what THIS class bounds: one actor hammering the
     * manifest/zip yields the window cap in rows, every later hit is only counted, and that count is
     * folded into the first row of the next window. Serving is never affected.
     */
    public function testBaitRowsPerActorAreBoundedAndSuppressedCountIsFolded(): void
    {
        $now = 1_700_000_000;
        $limiter = new BaitEventLimiter(3, 600, static function () use (&$now): int { return $now; });
        $r = $this->routerWith($limiter, $captured);

        for ($i = 0; $i < 5; $i++) {
            $captured = '';
            $r->handle(new RequestContext('GET', '/__dl/manifest', 'host=' . $this->host), '203.0.113.9');
            $this->assertJson($captured, "request {$i} is still served while suppressed");
        }
        $rows = $this->downloadRows('203.0.113.9');
        $this->assertCount(3, $rows, 'window cap');

        // Another actor is independent.
        $r->handle(new RequestContext('GET', '/__dl/backup.zip', 'host=' . $this->host), '203.0.113.10');
        $this->assertCount(1, $this->downloadRows('203.0.113.10'));

        // Next window: kept again, carrying the two dropped events in the body.
        $now += 601;
        $r->handle(new RequestContext('GET', '/__dl/manifest', 'host=' . $this->host), '203.0.113.9');
        $rows = $this->downloadRows('203.0.113.9');
        $this->assertCount(4, $rows);
        $this->assertStringContainsString('suppressed=2', (string) $rows[3]['body']);
        $this->assertStringContainsString('host=', (string) $rows[3]['body']);
    }

    public function testTelemetryFaultNeverChangesWhatIsServed(): void
    {
        $limiter = new BaitEventLimiter(3, 600, null, static function (): int { throw new \RuntimeException('shm gone'); }, static fn (): int => 0);
        $r = $this->routerWith($limiter, $captured);
        $r->handle(new RequestContext('GET', '/__dl/manifest', 'host=' . $this->host), '203.0.113.11');
        $this->assertJson($captured);
        $this->assertCount(1, $this->downloadRows('203.0.113.11'), 'a counter fault admits the event');
    }

    /** @return list<array<string,mixed>> */
    private function downloadRows(string $ip): array
    {
        return array_values(array_filter($this->hits->appended, static fn (array $e): bool => ($e['event'] ?? '') === 'download' && $e['ip'] === $ip));
    }

    private function routerWith(BaitEventLimiter $limiter, ?string &$captured): DownloadRouter
    {
        $captured = '';
        $factory = static function () use (&$captured): StreamEmitter {
            return new StreamEmitter(static function (string $b) use (&$captured): void { $captured .= $b; }, 0);
        };

        return new DownloadRouter($this->hits, self::SEED, "/* sw */", 100, 200, 100, 50, 20, 2, $factory, $limiter);
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

    public function recentEventCount(string $ip, string $event, int $sinceSeconds): int
    {
        return 0;
    }

    public function flagBulkScan(string $ip, int $hours): void
    {
    }

    public function isBulkFlagged(string $ip): bool
    {
        return false;
    }
}
