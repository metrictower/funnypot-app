<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Identity;

use Funnypot\App\Identity\IdentityInputs;
use Funnypot\App\Identity\IdentityKeyDeriver;
use Funnypot\App\Identity\IdentityPaths;
use Funnypot\Tests\App\Http\DashboardHttpServerTrait;
use PHPUnit\Framework\TestCase;

/**
 * Unique sentinels for the master, every private key, the raw persona override, the commitment and
 * the private path go through a REAL preparation and a REAL php -S front controller; none may
 * appear in a served response, a response header, the request log, the hit store, the error log,
 * the generated nginx vhost or the persistent manifest. The forced bootstrap fault goes through
 * demo/index.php's real global handler and must log only its code.
 */
final class IdentityLeakTest extends TestCase
{
    use DashboardHttpServerTrait;

    private const OVERRIDE = 'leak-sentinel-persona-override-7f3a9c';

    protected function tearDown(): void
    {
        $this->dashboardCleanupTmpDirs();
    }

    /** @return list<string> */
    private function sentinels(string $data, string $tag): array
    {
        $master = IdentityTestSupport::master($tag);
        $d = IdentityTestSupport::deriver($tag);
        $out = [
            IdentityKeyDeriver::encodeKey($master),
            bin2hex($master),
            base64_encode($master),
            self::OVERRIDE,
            $d->keysetCommitment(),
            $data . '/.funnypot',
            'install.secret',
        ];
        foreach (['coreRenderSalt', 'shellFilesystemKey', 'consoleSessionMacKey', 'dockerRegistryTokenKey', 'engagementAnalyticsKey', 'redisTelemetryFingerprintKey', 'postExploitStateKey'] as $m) {
            $out[] = IdentityKeyDeriver::encodeKey($d->{$m}());
            $out[] = bin2hex($d->{$m}());
        }

        return $out;
    }

    public function test_no_sentinel_reaches_any_sink_and_the_bootstrap_fault_logs_only_a_code(): void
    {
        $root = dirname(__DIR__, 2) . '/..';
        $root = (string) realpath($root);
        $data = (string) realpath($this->dashboardTempDir('fpleak_data'));
        $docroot = $this->dashboardTempDir('fpleak_doc');
        $tag = 'leak';

        $prepared = PreparedIdentityFixture::prepare($data, self::OVERRIDE, $tag, new IdentityInputs(
            secretEnv: IdentityTestSupport::canonicalMaster($tag),
            personaSeed: self::OVERRIDE,
            leDomain: 'admin.example.com',
        ));
        $prepared['result']->close();
        $paths = IdentityPaths::forStorage($data, $prepared['runtimeDir']);
        $sentinels = $this->sentinels($data, $tag);

        // Persistent + runtime artifacts that are NOT the key-bearing bundles themselves.
        $manifest = (string) file_get_contents($paths->manifestPath());
        foreach ($sentinels as $s) {
            if (str_starts_with($s, 'fpkc1_')) {
                continue; // the commitment is allowed ONLY in root/runtime integrity metadata
            }
            self::assertStringNotContainsString($s, $manifest, 'manifest leaked a sentinel');
        }
        self::assertFileDoesNotExist($paths->adminVhostPath(), 'no LE pair issued ⇒ no admin vhost');

        $env = [
            'PATH' => getenv('PATH') !== false ? (string) getenv('PATH') : '/usr/bin:/bin',
            'FUNNYPOT_DB' => $data . '/funnypot.sqlite',
            'FUNNYPOT_LOG' => $data . '/hits.log',
            'FUNNYPOT_GEO_DB' => $data . '/geo.csv',
            'FUNNYPOT_VULNS' => $data . '/vulns.json',
            'FUNNYPOT_LLM' => '0',
            'FUNNYPOT_DOCKER_API' => '1',
            'FUNNYPOT_ENGAGEMENT' => '1',
            'FUNNYPOT_TARPIT' => '1',
        ] + PreparedIdentityFixture::childEnv($prepared['runtimeDir']);
        foreach (['PHPRC', 'PHP_INI_SCAN_DIR'] as $iniVar) {
            $v = getenv($iniVar);
            if ($v !== false && $v !== '') {
                $env[$iniVar] = $v;
            }
        }

        [$proc, $pipes, $port] = $this->startDashboardServer($root . '/demo/index.php', $docroot, $env);
        try {
            $served = '';
            foreach ([
                ['GET', '/'], ['GET', '/.env'], ['GET', '/index.php?page=../../../../etc/passwd'], ['GET', '/wp-login.php'],
                ['GET', '/robots.txt'], ['GET', '/phpinfo.php'], ['GET', '/version'], ['GET', '/funnypot?feed=1'],
                ['POST', '/__console/exec', ['Content-Type' => 'application/json'], '{"host":"x","command":"id"}'],
                ['POST', '/containers/create', ['Content-Type' => 'application/json', 'X-Registry-Auth' => base64_encode('{"username":"u","password":"hunter2"}')], '{"Image":"alpine"}'],
            ] as $req) {
                [$status, $headers, $body] = $this->dashboardHttpRequest('127.0.0.1', $port, $req[0], $req[1], $req[2] ?? [], $req[3] ?? '');
                self::assertNotSame(0, $status, "{$req[1]} answered");
                self::assertLessThan(500, $status, "{$req[1]} must not 5xx");
                $served .= $body . "\n" . json_encode($headers) . "\n";
            }
            $stderr = (string) stream_get_contents($pipes[2]);
        } finally {
            $this->stopDashboardServer($proc, $pipes);
        }
        $sinks = [
            'served responses' => $served,
            'server error log' => $stderr,
            'hits.log' => (string) @file_get_contents($data . '/hits.log'),
            'hit store bytes' => (string) @file_get_contents($data . '/funnypot.sqlite'),
            'console store bytes' => (string) @file_get_contents($data . '/console.sqlite'),
            'docker store bytes' => (string) @file_get_contents($data . '/docker.sqlite'),
            'engagement store bytes' => (string) @file_get_contents($data . '/engagement.sqlite'),
        ];
        self::assertStringContainsString('x-powered-by', $served, 'sanity: the front controller served with its persona header');
        foreach ($sinks as $name => $text) {
            foreach ($sentinels as $s) {
                self::assertStringNotContainsString($s, $text, "{$name} leaked a sentinel");
            }
        }
        self::assertStringNotContainsString($prepared['runtimeDir'], $served, 'served bytes leaked the runtime root');
        self::assertStringNotContainsString($data, $served, 'served bytes leaked the data dir');

        // Forced bootstrap fault through the REAL global handler: a tampered (group-writable) bundle.
        chmod($paths->httpBundlePath(), 0666);
        [$proc, $pipes, $port] = $this->startDashboardServer($root . '/demo/index.php', $docroot, $env);
        try {
            [$status, , $body] = $this->dashboardHttpRequest('127.0.0.1', $port, 'GET', '/.env');
            self::assertSame(404, $status, 'a bootstrap fault serves the plain 404, never a 500 or a fallback fake');
            self::assertSame('<!doctype html><title>404 Not Found</title>404 Not Found', $body);
            usleep(200000);
            $stderr = (string) stream_get_contents($pipes[2]);
        } finally {
            $this->stopDashboardServer($proc, $pipes);
        }
        self::assertStringContainsString('funnypot identity: bundle-unsafe', $stderr, 'only the public code is logged');
        self::assertStringNotContainsString('IdentityBootstrapException', $stderr);
        self::assertStringNotContainsString($data, $stderr, 'no private path');
        self::assertStringNotContainsString('.php:', $stderr, 'no source location');
        self::assertStringNotContainsString('funnypot uncaught', $stderr, 'never routed through the generic message/file/line logger');
        foreach ($sentinels as $s) {
            self::assertStringNotContainsString($s, $stderr);
        }
    }
}
