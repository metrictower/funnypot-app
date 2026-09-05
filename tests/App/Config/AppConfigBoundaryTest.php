<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Config;

use Funnypot\App\Config\AppConfig;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

/**
 * AppConfig owns no identity, so every background worker that builds one runs with NO identity
 * material anywhere — no runtime bundle, no master, no persona variable — and still completes.
 */
final class AppConfigBoundaryTest extends TestCase
{
    private string $data = '';

    protected function setUp(): void
    {
        if (!function_exists('proc_open')) {
            self::markTestSkipped('proc_open disabled');
        }
        $this->data = sys_get_temp_dir() . '/fp_cfgb_' . bin2hex(random_bytes(5));
        mkdir($this->data, 0777, true);
    }

    protected function tearDown(): void
    {
        if ($this->data !== '' && is_dir($this->data)) {
            exec('rm -rf ' . escapeshellarg($this->data));
        }
    }

    public function test_appconfig_reflects_no_identity_or_master_property(): void
    {
        $rc = new ReflectionClass(AppConfig::class);
        foreach ($rc->getProperties() as $p) {
            self::assertDoesNotMatchRegularExpression('/persona|master|installSecret|tlsCert|tlsKey/i', $p->getName(), "AppConfig owns identity property {$p->getName()}");
        }
        $src = (string) file_get_contents((string) $rc->getFileName());
        self::assertStringNotContainsString('PersonaIdentity', $src, 'AppConfig no longer derives a persona');
        self::assertDoesNotMatchRegularExpression("/PERSONA_SE(?:ED|CRET)'\\s*,\\s*'funnypot'/", $src, 'no fleet-literal persona fallback');
        self::assertStringNotContainsString('FUNNYPOT_PERSONA', $src, 'no persona variable is read here');
    }

    /** Every script under demo/ that builds an AppConfig is enumerated, so a new worker cannot slip past. */
    public function test_every_worker_that_builds_appconfig_is_covered(): void
    {
        $root = dirname(__DIR__, 3);
        $builders = [];
        foreach (glob($root . '/demo/*.php') ?: [] as $f) {
            if (str_contains((string) file_get_contents($f), 'AppConfig::from')) {
                $builders[] = basename($f);
            }
        }
        sort($builders);
        self::assertSame(
            ['abuse-drain.php', 'blocklist-refresh.php', 'index.php', 'listen.php', 'retention.php', 'rollup.php', 'threatintel-drain.php'],
            $builders,
            'a demo/ script started building AppConfig — add it to the identity-free worker run below (or to the identity-loading roots)'
        );
    }

    /** @dataProvider workers */
    public function test_background_worker_runs_without_any_identity(string $script): void
    {
        $root = dirname(__DIR__, 3);
        $env = [
            'PATH' => (string) (getenv('PATH') ?: '/usr/bin:/bin'),
            'FUNNYPOT_DB' => $this->data . '/funnypot.sqlite',
            'FUNNYPOT_LOG' => $this->data . '/hits.log',
            'FUNNYPOT_INTEL_DB' => $this->data . '/intel.sqlite',
            'FUNNYPOT_TARPIT_DB' => $this->data . '/tarpit.sqlite',
            'FUNNYPOT_LLM_CACHE_DB' => $this->data . '/llm.sqlite',
            'FUNNYPOT_VULNS' => $this->data . '/vulns.json',
            // Point the runtime root at a NON-existent dir: a worker that needed identity would fail here.
            'FUNNYPOT_IDENTITY_RUNTIME_DIR' => $this->data . '/no-runtime',
        ];
        foreach (['PHPRC', 'PHP_INI_SCAN_DIR'] as $k) {
            $v = getenv($k);
            if ($v !== false && $v !== '') {
                $env[$k] = $v;
            }
        }
        $pipes = [];
        $p = proc_open([PHP_BINARY, $root . '/demo/' . $script], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $this->data, $env);
        self::assertIsResource($p);
        $out = (string) stream_get_contents($pipes[1]);
        $err = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $rc = proc_close($p);
        self::assertSame(0, $rc, "{$script} failed without identity (rc={$rc}): {$err}");
        self::assertStringNotContainsStringIgnoringCase('identity', $out . $err, "{$script} touched identity");
        self::assertStringNotContainsString('Fatal', $out . $err);
        self::assertFileDoesNotExist($this->data . '/.funnypot', 'a worker must never create identity state');
    }

    /** @return array<string,array{0:string}> */
    public static function workers(): array
    {
        return [
            'retention' => ['retention.php'],
            'rollup' => ['rollup.php'],
            'abuse-drain' => ['abuse-drain.php'],
            'threatintel-drain' => ['threatintel-drain.php'],
            'blocklist-refresh' => ['blocklist-refresh.php'],
        ];
    }
}
