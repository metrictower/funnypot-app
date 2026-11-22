<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\Tests\App\Identity\PreparedIdentityFixture;
use Funnypot\Tests\App\Tarpit\Mint\MintHarness;
use PHPUnit\Framework\TestCase;

/** The real composition root wires the SSRF decoy only when every gate holds, and off answers as today. */
final class SsrfFrontControllerTest extends TestCase
{
    private string $dir = '';

    protected function setUp(): void
    {
        if (!function_exists('proc_open') || !extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('proc_open / pdo_sqlite required');
        }
        $dir = sys_get_temp_dir() . '/fp-ssrf-front-' . bin2hex(random_bytes(8));
        self::assertTrue(mkdir($dir, 0700));
        $this->dir = (string) realpath($dir);
        $prepared = PreparedIdentityFixture::prepare($this->dir, 'ssrf-front');
        $prepared['result']->close();
    }

    protected function tearDown(): void
    {
        if ($this->dir !== '' && is_dir($this->dir)) {
            foreach ([$this->dir . '/blocked'] as $d) {
                if (is_dir($d)) {
                    chmod($d, 0700);
                }
            }
            MintHarness::removeTree($this->dir);
        }
    }

    public function test_wired_only_when_every_gate_holds(): void
    {
        $baseline = $this->request(['FUNNYPOT_TARPIT_SSRF' => '0'], '/settings/webhooks');
        self::assertFalse($baseline['ssrf']);
        self::assertSame(404, $baseline['status']);
        foreach ([
            'flag off' => ['FUNNYPOT_TARPIT_SSRF' => '0'],
            'token mint off' => ['FUNNYPOT_TARPIT_TOKEN_MINT' => '0'],
            'tarpit off' => ['FUNNYPOT_TARPIT' => '0'],
        ] as $case => $env) {
            $r = $this->request($env, '/settings/webhooks');
            self::assertFalse($r['ssrf'], $case);
            self::assertSame($baseline['body'], $r['body'], "{$case}: today's answer, byte for byte");
        }
        self::assertFileDoesNotExist($this->dir . '/ssrf-decoy.sqlite', 'an unwired decoy never creates its store');
        $on = $this->request([], '/settings/webhooks');
        self::assertTrue($on['ssrf'] && $on['wired'], $on['err']);
        self::assertSame(303, $on['status'], 'armed: a webhooks page without a session goes to sign-in');
        self::assertFileExists($this->dir . '/ssrf-decoy.sqlite');
        $api = $this->request([], '/api/v2/user/hooks');
        self::assertSame(401, $api['status']);
        self::assertStringContainsString('Authentication required', $api['body']);
    }

    public function test_a_failed_migration_logs_its_code_and_leaves_the_decoy_unwired(): void
    {
        mkdir($this->dir . '/blocked', 0500);
        $r = $this->request(['FUNNYPOT_SSRF_DB' => $this->dir . '/blocked/sub/ssrf-decoy.sqlite'], '/settings/webhooks');
        self::assertFalse($r['ssrf']);
        self::assertTrue($r['wired'], 'the token-mint surface stays wired, without the extension');
        self::assertStringContainsString('code=ssrf-decoy-migration-failed', $r['err']);
        self::assertSame(404, $r['status']);
    }

    /** @param array<string,string> $overrides @return array{status:int,wired:bool,ssrf:bool,body:string,err:string} */
    private function request(array $overrides, string $target): array
    {
        return self::runFixture($this->dir, $overrides, $target);
    }

    /**
     * Run the real composition root once through tests/Fixtures/ssrf/front-controller.php.
     *
     * @param array<string,string> $overrides
     * @return array{status:int,wired:bool,ssrf:bool,wiki:?array,body:string,err:string}
     */
    public static function runFixture(string $dir, array $overrides, string $target): array
    {
        $root = dirname(__DIR__, 3);
        $env = $overrides + [
            'FUNNYPOT_IDENTITY_RUNTIME_DIR' => $dir . '/runtime',
            'FUNNYPOT_DB' => $dir . '/funnypot.sqlite', 'FUNNYPOT_LOG' => $dir . '/hits.log',
            'FUNNYPOT_INTEL_DB' => $dir . '/intel.sqlite', 'FUNNYPOT_GEO_DB' => $dir . '/geo.csv',
            'FUNNYPOT_LLM_CACHE_DB' => $dir . '/llm-cache.sqlite', 'FUNNYPOT_VULNS' => $dir . '/vulns.json',
            'FUNNYPOT_TARPIT_DB' => $dir . '/tarpit.sqlite', 'FUNNYPOT_TOKEN_MINT_DB' => $dir . '/token-mint.sqlite',
            'FUNNYPOT_SSRF_DB' => $dir . '/ssrf-decoy.sqlite',
            'FUNNYPOT_SERVICE_STATUS_DIR' => '../invalid-fixture-path',
            'FUNNYPOT_TARPIT' => '1', 'FUNNYPOT_TARPIT_TOKEN_MINT' => '1', 'FUNNYPOT_TARPIT_SSRF' => '1', 'FUNNYPOT_ATTRITION' => '0',
            'FUNNYPOT_LATENCY_MS' => '0', 'FUNNYPOT_JITTER_MS' => '0', 'FUNNYPOT_TARPIT_LATENCY_MS' => '0',
            'FUNNYPOT_LLM' => '0', 'FUNNYPOT_AI_API' => '0', 'FUNNYPOT_DOCKER_API' => '0',
            'FUNNYPOT_SLEEP_DECOY' => '0', 'FUNNYPOT_ENDLESS_DOWNLOAD' => '0',
            'FUNNYPOT_ABUSEIPDB_REPORT' => '0', 'FUNNYPOT_THREATINTEL_REPORT' => '0',
            'FUNNYPOT_CAPTURE_RAW' => '0', 'FUNNYPOT_ENGAGEMENT' => '0',
        ];
        $env['PATH'] = (string) (getenv('PATH') ?: '/usr/bin:/bin');
        $process = proc_open([PHP_BINARY, '-d', 'memory_limit=256M', '-d', 'max_execution_time=10', '-d', 'log_errors=1', '-d', 'error_log=',
            $root . '/tests/Fixtures/ssrf/front-controller.php', 'GET', $target],
            [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $root, $env);
        self::assertIsResource($process);
        $out = (string) stream_get_contents($pipes[1]);
        $err = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        self::assertSame(0, proc_close($process), substr($err, 0, 512));
        $result = json_decode($out, true);
        self::assertIsArray($result, substr($out . $err, 0, 512));
        self::assertStringNotContainsString('funnypot uncaught', $err);
        $result['err'] = $err;

        return $result;
    }
}
