<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\Tests\App\Identity\PreparedIdentityFixture;
use PHPUnit\Framework\TestCase;

/** The main/FP-0272 merge must retain both composition seams, not merely compile after marker removal. */
final class AttritionFrontControllerIntegrationTest extends TestCase
{
    public function test_real_bootstrap_retains_service_fallback_and_mounted_attrition_on_one_budget(): void
    {
        $dir = sys_get_temp_dir() . '/fp-attrition-integration-' . bin2hex(random_bytes(8));
        self::assertTrue(mkdir($dir, 0700));
        $dir = (string) realpath($dir);
        try {
            $prepared = PreparedIdentityFixture::prepare($dir, 'attrition-integration');
            $prepared['result']->close();
            unset($prepared);
            $off = $this->request($dir, false, 'GET', '/admin/audit-archive/page-000002');
            self::assertSame(200, $off['status']);
            self::assertSame('neutral', $off['profile']);
            self::assertFalse($off['attrition']);
            self::assertNull($off['entry']);
            self::assertFileDoesNotExist($dir . '/attrition.sqlite');

            $page = $this->request($dir, true, 'GET', '/admin/audit-archive/page-000002');
            self::assertSame(200, $page['status']);
            self::assertSame('neutral', $page['profile'], 'Malformed status path must retain main\'s safe profile reader.');
            self::assertTrue($page['attrition']);
            self::assertTrue($page['shared_budget']);
            self::assertIsString($page['entry']);
            self::assertSame(strlen('/admin/export/jobs/') + 117, strlen($page['entry']));

            $job = $this->request($dir, true, 'POST', $page['entry']);
            self::assertSame(202, $job['status'], 'Actual Router must receive the attrition controller.');
            self::assertSame('audit-export-job/v1', $job['job_schema']);
            self::assertSame('queued', $job['job_state']);
            self::assertSame('neutral', $job['profile']);
            self::assertTrue($job['shared_budget']);
            self::assertLessThanOrEqual(4096, $job['body_bytes']);
        } finally {
            foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST) as $file) {
                $file->isDir() && !$file->isLink() ? rmdir($file->getPathname()) : unlink($file->getPathname());
            }
            rmdir($dir);
        }
    }

    private function request(string $dir, bool $enabled, string $method, string $target): array
    {
        $root = dirname(__DIR__, 3);
        // Replace, do not inherit, the environment: synthetic storage, no keys/reporters/models/listeners.
        $env = [
            'FUNNYPOT_IDENTITY_RUNTIME_DIR' => $dir . '/runtime',
            'FUNNYPOT_DB' => $dir . '/funnypot.sqlite', 'FUNNYPOT_LOG' => $dir . '/hits.log',
            'FUNNYPOT_INTEL_DB' => $dir . '/intel.sqlite', 'FUNNYPOT_GEO_DB' => $dir . '/geo.csv',
            'FUNNYPOT_LLM_CACHE_DB' => $dir . '/llm-cache.sqlite', 'FUNNYPOT_VULNS' => $dir . '/vulns.json',
            'FUNNYPOT_TARPIT_DB' => $dir . '/tarpit.sqlite', 'FUNNYPOT_ATTRITION_DB' => $dir . '/attrition.sqlite',
            'FUNNYPOT_SERVICE_STATUS_DIR' => '../invalid-fixture-path',
            'FUNNYPOT_TARPIT' => '1', 'FUNNYPOT_ATTRITION' => $enabled ? '1' : '0',
            'FUNNYPOT_LATENCY_MS' => '0', 'FUNNYPOT_JITTER_MS' => '0', 'FUNNYPOT_TARPIT_LATENCY_MS' => '0',
            'FUNNYPOT_LLM' => '0', 'FUNNYPOT_AI_API' => '0', 'FUNNYPOT_DOCKER_API' => '0',
            'FUNNYPOT_SLEEP_DECOY' => '0', 'FUNNYPOT_ENDLESS_DOWNLOAD' => '0',
            'FUNNYPOT_ABUSEIPDB_REPORT' => '0', 'FUNNYPOT_THREATINTEL_REPORT' => '0',
            'FUNNYPOT_CAPTURE_RAW' => '0', 'FUNNYPOT_ENGAGEMENT' => '0',
        ];
        $process = proc_open([PHP_BINARY, '-d', 'memory_limit=256M', '-d', 'max_execution_time=10',
            $root . '/tests/Fixtures/attrition/front-controller.php', $method, $target],
            [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $root, $env);
        self::assertIsResource($process);
        foreach ($pipes as $pipe) {
            stream_set_blocking($pipe, false);
        }
        $out = $err = '';
        $deadline = hrtime(true) + 15_000_000_000;
        try {
            do {
                $out .= stream_get_contents($pipes[1]);
                $err .= stream_get_contents($pipes[2]);
                $state = proc_get_status($process);
                if (strlen($out) + strlen($err) >= 65536 || hrtime(true) >= $deadline) {
                    self::fail('Bootstrap fixture exceeded 15 seconds / 64 KiB.');
                }
                if ($state['running']) {
                    usleep(10000);
                }
            } while ($state['running']);
            $out .= stream_get_contents($pipes[1]);
            $err .= stream_get_contents($pipes[2]);
            self::assertSame(0, $state['exitcode'], substr($err, 0, 512));
            $result = json_decode($out, true);
            self::assertIsArray($result, substr($out . $err, 0, 512));
            self::assertStringNotContainsString('funnypot uncaught', $err);
            return $result;
        } finally {
            if (proc_get_status($process)['running']) {
                proc_terminate($process, 9);
            }
            foreach ($pipes as $pipe) {
                fclose($pipe);
            }
            proc_close($process);
        }
    }
}
