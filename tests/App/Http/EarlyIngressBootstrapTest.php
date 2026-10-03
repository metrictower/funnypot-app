<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use PHPUnit\Framework\TestCase;

final class EarlyIngressBootstrapTest extends TestCase
{
    private const BODY = '<!doctype html><title>414 URI Too Long</title>URI Too Long';

    public function test_overlong_target_never_bootstraps_or_persists_and_faults_use_the_same_414(): void
    {
        foreach (['none', 'throw', 'fatal'] as $fault) {
            $target = str_pad('/robots.txt?reject-sentinel-', 4097, 'q');
            [$result, $stderr, $files] = $this->request($target, $fault, 'POST');
            self::assertSame(414, $result['status']);
            self::assertSame(self::BODY, base64_decode($result['body']));
            self::assertFalse($result['geo_included']);
            self::assertSame(0, $result['body_reads']);
            foreach (['Config\\ConfigStore', 'Config\\AppConfig', 'Storage\\SqliteHitStore', 'Storage\\RawCapture'] as $class) {
                self::assertNotContains('Funnypot\\App\\' . $class, $result['classes']);
            }
            self::assertNotContains('Funnypot\\Core\\RequestContext', $result['classes']);
            self::assertSame('', $stderr, 'neither the PHP logger nor the fault handler may leak the target');
            self::assertSame(['runtime/identity-http/http.json'], $files, 'only the fixture-owned bundle exists');
        }
    }

    public function test_exactly_4096_keeps_real_known_route_and_miss_bootstrap_and_sink_controls(): void
    {
        foreach (['/.env?' => 200, '/ingress-clean-control-z94q?' => 404] as $prefix => $status) {
            [$result, $stderr, $files] = $this->request(str_pad($prefix, 4096, 'q'));
            self::assertSame($status, $result['status']);
            self::assertNotSame(self::BODY, base64_decode($result['body']));
            self::assertTrue($result['geo_included']);
            self::assertSame(0, $result['body_reads'], 'GET retains its existing no-body-read behavior');
            foreach (['Config\\ConfigStore', 'Config\\AppConfig', 'Storage\\SqliteHitStore', 'Storage\\RawCapture'] as $class) {
                self::assertContains('Funnypot\\App\\' . $class, $result['classes']);
            }
            self::assertContains('funnypot.sqlite', $files);
            self::assertContains('raw-capture.sqlite', $files);
            self::assertContains('hits.log', $files);
            self::assertStringContainsString('192.0.2.13', $stderr, 'accepted request diagnostic sink is exercised');
            self::assertGreaterThan(0, $result['sink_rows']['hits']);
            self::assertGreaterThan(0, $result['sink_rows']['raw_requests']);
            self::assertLessThanOrEqual(400, $result['max_hit_path']);
            if ($status === 200) {
                self::assertGreaterThan(0, $result['sink_rows']['abuse_queue']);
                self::assertGreaterThan(0, $result['sink_rows']['ti_queue']);
            }
        }
    }

    public function test_accepted_write_method_exercises_the_body_read_spy(): void
    {
        [$result] = $this->request('/ingress-clean-control-z94q', 'none', 'POST');
        self::assertSame(1, $result['body_reads']);
        self::assertTrue($result['geo_included']);
    }

    public function test_missing_and_non_string_targets_reach_the_actual_slash_fallback(): void
    {
        [$control] = $this->request('/');
        foreach (['array', 'object', 'integer', 'false', 'true', 'null', 'missing'] as $shape) {
            [$result, $stderr] = $this->request('/', 'none', 'GET', $shape);
            self::assertSame($control['status'], $result['status'], $shape);
            self::assertTrue($result['target_is_slash'], $shape);
            self::assertTrue($result['geo_included'], $shape);
            self::assertContains('Funnypot\\Core\\RequestContext', $result['classes'], $shape);
            self::assertStringNotContainsString('funnypot uncaught', $stderr, $shape);
        }
    }

    /** @return array{array,string,list<string>} */
    private function request(string $target, string $fault = 'none', string $method = 'GET', string $shape = 'string'): array
    {
        $root = dirname(__DIR__, 3);
        $data = sys_get_temp_dir() . '/fp-ingress-' . bin2hex(random_bytes(8));
        self::assertTrue(mkdir($data, 0700));
        $data = (string) realpath($data);
        $env = [
            'FUNNYPOT_TEST_INGRESS_DATA' => $data,
            'FUNNYPOT_IDENTITY_RUNTIME_DIR' => $data . '/runtime',
            'FUNNYPOT_DB' => $data . '/funnypot.sqlite', 'FUNNYPOT_LOG' => $data . '/hits.log',
            'FUNNYPOT_INTEL_DB' => $data . '/intel.sqlite', 'FUNNYPOT_GEO_DB' => $data . '/geo.csv',
            'FUNNYPOT_LLM_CACHE_DB' => $data . '/llm-cache.sqlite',
            'FUNNYPOT_TARPIT_DB' => $data . '/tarpit.sqlite',
            'FUNNYPOT_VULNS' => $data . '/vulns.json', 'FUNNYPOT_CAPTURE_RAW' => '1',
            'FUNNYPOT_LLM' => '0', 'FUNNYPOT_AI_API' => '0', 'FUNNYPOT_TARPIT' => '0',
            'FUNNYPOT_SLEEP_DECOY' => '0', 'FUNNYPOT_ABUSEIPDB_REPORT' => '1',
            'FUNNYPOT_ABUSEIPDB_KEY' => 'ingress-fixture-not-a-credential',
            'FUNNYPOT_THREATINTEL_REPORT' => '1', 'FUNNYPOT_THREATINTEL_KEY' => 'ingress-fixture-not-a-credential',
            'FUNNYPOT_THREATINTEL_URL' => 'http://127.0.0.1:1', 'FUNNYPOT_SELF_IPS' => '127.0.0.1',
        ];
        $proc = null;
        $pipes = [];
        try {
            $proc = proc_open([PHP_BINARY, '-d', 'memory_limit=256M', '-d', 'max_execution_time=10',
                $root . '/tests/Fixtures/ingress/front-controller.php', base64_encode($target), $fault, $method, $shape],
                [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']], $pipes, $root, $env);
            self::assertIsResource($proc);
            fclose($pipes[0]);
            unset($pipes[0]);
            stream_set_blocking($pipes[1], false);
            stream_set_blocking($pipes[2], false);
            $stdout = $stderr = '';
            $until = hrtime(true) + 15_000_000_000;
            do {
                $stdout .= stream_get_contents($pipes[1]);
                $stderr .= stream_get_contents($pipes[2]);
                if (strlen($stdout) + strlen($stderr) >= 2 * 1024 * 1024 || hrtime(true) >= $until) {
                    self::fail('child exceeded the 2 MiB output / 15 second wall budget');
                }
                $state = proc_get_status($proc);
                if ($state['running']) {
                    usleep(10000);
                }
            } while ($state['running']);
            $stdout .= stream_get_contents($pipes[1]);
            $stderr .= stream_get_contents($pipes[2]);
            $result = json_decode($stdout, true);
            self::assertIsArray($result, $stderr . substr($stdout, 0, 512));
            $result['sink_rows'] = [];
            foreach (['funnypot.sqlite' => ['hits'], 'raw-capture.sqlite' => ['raw_requests'],
                'intel.sqlite' => ['abuse_queue', 'ti_queue']] as $file => $tables) {
                if (is_file($data . '/' . $file)) {
                    $db = new \PDO('sqlite:' . $data . '/' . $file);
                    foreach ($tables as $table) {
                        if ($db->query("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='" . $table . "'")->fetchColumn()) {
                            $result['sink_rows'][$table] = (int) $db->query('SELECT COUNT(*) FROM ' . $table)->fetchColumn();
                        }
                    }
                    if ($file === 'funnypot.sqlite') {
                        $result['max_hit_path'] = (int) $db->query('SELECT MAX(length(path)) FROM hits')->fetchColumn();
                    }
                    $db = null;
                }
            }
            $files = [];
            foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($data, \FilesystemIterator::SKIP_DOTS)) as $file) {
                $files[] = substr($file->getPathname(), strlen($data) + 1);
            }
            sort($files);
            return [$result, $stderr, $files];
        } finally {
            if (is_resource($proc)) {
                if (proc_get_status($proc)['running']) {
                    proc_terminate($proc, 9);
                }
                foreach ($pipes as $pipe) {
                    if (is_resource($pipe)) {
                        fclose($pipe);
                    }
                }
                proc_close($proc);
            }
            foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($data, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST) as $file) {
                $file->isDir() && !$file->isLink() ? rmdir($file->getPathname()) : unlink($file->getPathname());
            }
            rmdir($data);
        }
    }
}
