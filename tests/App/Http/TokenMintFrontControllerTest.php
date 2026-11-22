<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Identity\IdentityPaths;
use Funnypot\Tests\App\Identity\PreparedIdentityFixture;
use PHPUnit\Framework\TestCase;

/**
 * The composition root wires the token-mint surface only when all four gates hold (the tarpit and the
 * surface's own flag on, public mode, the bundle carries its key, its store migrates); with any gate
 * failing its paths answer exactly as today and a failed gate logs its fixed code.
 */
final class TokenMintFrontControllerTest extends TestCase
{
    private string $dir = '';

    protected function setUp(): void
    {
        if (!function_exists('proc_open') || !extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('proc_open / pdo_sqlite required');
        }
        $dir = sys_get_temp_dir() . '/fp-token-mint-front-' . bin2hex(random_bytes(8));
        self::assertTrue(mkdir($dir, 0700));
        $this->dir = (string) realpath($dir);
        $prepared = PreparedIdentityFixture::prepare($this->dir, 'token-mint-front');
        $prepared['result']->close();
    }

    protected function tearDown(): void
    {
        if ($this->dir !== '' && is_dir($this->dir)) {
            exec('chmod -R u+rwx ' . escapeshellarg($this->dir) . ' 2>/dev/null; rm -rf ' . escapeshellarg($this->dir));
        }
    }

    public function test_wired_only_when_every_gate_holds(): void
    {
        $baseline = $this->request(['FUNNYPOT_TARPIT_TOKEN_MINT' => '0'], '/settings/tokens');
        self::assertFalse($baseline['wired']);
        self::assertSame(404, $baseline['status']);
        foreach ([
            'tarpit off' => ['FUNNYPOT_TARPIT' => '0'],
            'flag off' => ['FUNNYPOT_TARPIT_TOKEN_MINT' => '0'],
            'stealth' => ['FUNNYPOT_MODE' => 'stealth'],
        ] as $case => $env) {
            $r = $this->request($env, '/settings/tokens');
            self::assertFalse($r['wired'], $case);
            self::assertFalse($r['front'], $case);
            if ($case !== 'stealth') {
                self::assertSame($baseline['status'], $r['status'], $case);
                self::assertSame($baseline['body'], $r['body'], "{$case}: today's answer, byte for byte");
            }
        }
        self::assertFileDoesNotExist($this->dir . '/token-mint.sqlite', 'an unwired surface never creates its store');

        $on = $this->request([], '/settings/tokens');
        self::assertTrue($on['wired'] && $on['front'], $on['err']);
        self::assertSame(303, $on['status'], 'armed: an account page without a session goes to sign-in');
        self::assertFileExists($this->dir . '/token-mint.sqlite');
    }

    public function test_a_failed_migration_logs_its_code_and_leaves_the_surface_unwired(): void
    {
        mkdir($this->dir . '/blocked', 0500);
        $r = $this->request(['FUNNYPOT_TOKEN_MINT_DB' => $this->dir . '/blocked/sub/token-mint.sqlite'], '/settings/tokens');
        self::assertFalse($r['wired']);
        self::assertSame(404, $r['status']);
        self::assertStringContainsString('code=token-mint-migration-failed', $r['err']);
    }

    public function test_an_old_bundle_without_the_key_logs_its_code_and_leaves_the_surface_unwired(): void
    {
        $paths = IdentityPaths::forStorage($this->dir, $this->dir . '/runtime');
        $p = $paths->httpBundlePath();
        $doc = json_decode((string) file_get_contents($p), true);
        unset($doc['payload']['token_mint_key']);
        chmod($p, 0600);
        file_put_contents($p, (string) json_encode($doc, JSON_UNESCAPED_SLASHES));
        chmod($p, 0640);
        $r = $this->request([], '/settings/tokens');
        self::assertFalse($r['wired']);
        self::assertSame(404, $r['status']);
        self::assertStringContainsString('code=token-mint-key-missing', $r['err']);
    }

    /** @param array<string,string> $overrides @return array{status:int,wired:bool,front:bool,body:string,err:string} */
    private function request(array $overrides, string $target): array
    {
        $root = dirname(__DIR__, 3);
        $dir = $this->dir;
        $env = $overrides + [
            'FUNNYPOT_IDENTITY_RUNTIME_DIR' => $dir . '/runtime',
            'FUNNYPOT_DB' => $dir . '/funnypot.sqlite', 'FUNNYPOT_LOG' => $dir . '/hits.log',
            'FUNNYPOT_INTEL_DB' => $dir . '/intel.sqlite', 'FUNNYPOT_GEO_DB' => $dir . '/geo.csv',
            'FUNNYPOT_LLM_CACHE_DB' => $dir . '/llm-cache.sqlite', 'FUNNYPOT_VULNS' => $dir . '/vulns.json',
            'FUNNYPOT_TARPIT_DB' => $dir . '/tarpit.sqlite', 'FUNNYPOT_TOKEN_MINT_DB' => $dir . '/token-mint.sqlite',
            'FUNNYPOT_SERVICE_STATUS_DIR' => '../invalid-fixture-path',
            'FUNNYPOT_TARPIT' => '1', 'FUNNYPOT_TARPIT_TOKEN_MINT' => '1', 'FUNNYPOT_ATTRITION' => '0',
            'FUNNYPOT_LATENCY_MS' => '0', 'FUNNYPOT_JITTER_MS' => '0', 'FUNNYPOT_TARPIT_LATENCY_MS' => '0',
            'FUNNYPOT_LLM' => '0', 'FUNNYPOT_AI_API' => '0', 'FUNNYPOT_DOCKER_API' => '0',
            'FUNNYPOT_SLEEP_DECOY' => '0', 'FUNNYPOT_ENDLESS_DOWNLOAD' => '0',
            'FUNNYPOT_ABUSEIPDB_REPORT' => '0', 'FUNNYPOT_THREATINTEL_REPORT' => '0',
            'FUNNYPOT_CAPTURE_RAW' => '0', 'FUNNYPOT_ENGAGEMENT' => '0',
        ];
        $env['PATH'] = (string) (getenv('PATH') ?: '/usr/bin:/bin');
        $process = proc_open([PHP_BINARY, '-d', 'memory_limit=256M', '-d', 'max_execution_time=10', '-d', 'log_errors=1', '-d', 'error_log=',
            $root . '/tests/Fixtures/token-mint/front-controller.php', 'GET', $target],
            [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $root, $env);
        self::assertIsResource($process);
        $out = (string) stream_get_contents($pipes[1]);
        $err = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $code = proc_close($process);
        self::assertSame(0, $code, substr($err, 0, 512));
        $result = json_decode($out, true);
        self::assertIsArray($result, substr($out . $err, 0, 512));
        self::assertStringNotContainsString('funnypot uncaught', $err);
        $result['err'] = $err;

        return $result;
    }
}
