<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Identity;

use Funnypot\App\Identity\IdentityInputs;
use PHPUnit\Framework\TestCase;

/**
 * demo/entrypoint.sh with every child command stubbed: identity:prepare is the FIRST consequential
 * command; when it fails nothing else starts; when it succeeds php-fpm, every listener and every
 * worker run WITHOUT any of the seven identity inputs in their environment (portable proof through
 * each stub's own env dump, plus /proc/<pid>/environ where the kernel offers it), while the runtime
 * dir path is kept so children can find their bundle.
 */
final class EntrypointOrderTest extends TestCase
{
    private string $tmp = '';

    /** Unique VALUES, so the proof is that the value is gone, not merely the name. */
    private const SENTINELS = [
        'FUNNYPOT_INSTALL_SECRET_FILE' => '/sentinel/master-file-6d2f',
        'FUNNYPOT_INSTALL_SECRET' => 'funnypot-install-secret-v1:sentinel-raw-master-value-9c4e0000000000',
        'FUNNYPOT_PERSONA_SEED' => 'sentinel-persona-seed-1b7a',
        'FUNNYPOT_PERSONA_SECRET' => 'sentinel-persona-secret-3e9d',
        'FUNNYPOT_TLS_CERT_FILE' => '/sentinel/tls-cert-5a1c.pem',
        'FUNNYPOT_TLS_KEY_FILE' => '/sentinel/tls-key-7f0b.pem',
        'FUNNYPOT_FS_SECRET' => 'sentinel-fs-secret-2c8e',
    ];

    protected function setUp(): void
    {
        if (!function_exists('proc_open') || !is_executable('/bin/sh')) {
            self::markTestSkipped('needs proc_open and /bin/sh');
        }
        $this->tmp = sys_get_temp_dir() . '/fp_entry_' . bin2hex(random_bytes(5));
        mkdir($this->tmp . '/bin', 0755, true);
        mkdir($this->tmp . '/out', 0755);
        mkdir($this->tmp . '/confd', 0755);
        $this->stub('php', <<<'SH'
#!/bin/sh
echo "php $*" >> "$FP_STUB_DIR/calls.log"
case "$*" in
  *identity:prepare*) env > "$FP_STUB_DIR/env.prepare"; exit "${FP_PREPARE_RC:-0}" ;;
  */listen.php*) env > "$FP_STUB_DIR/env.listen.$2.$$"; exit 0 ;;
  *) env > "$FP_STUB_DIR/env.worker.$$"; exit 0 ;;
esac
SH);
        $this->stub('php-fpm', <<<'SH'
#!/bin/sh
echo "php-fpm $*" >> "$FP_STUB_DIR/calls.log"
env > "$FP_STUB_DIR/env.php-fpm"
if [ -r "/proc/$$/environ" ]; then cat "/proc/$$/environ" > "$FP_STUB_DIR/environ.php-fpm"; fi
exit 0
SH);
        $this->stub('nginx', <<<'SH'
#!/bin/sh
echo "nginx $*" >> "$FP_STUB_DIR/calls.log"
env > "$FP_STUB_DIR/env.nginx"
exit 0
SH);
        // Every background loop sleeps between iterations; killing the loop's subshell ends it.
        $this->stub('sleep', <<<'SH'
#!/bin/sh
kill "$PPID" 2>/dev/null
exit 0
SH);
    }

    protected function tearDown(): void
    {
        if ($this->tmp !== '' && is_dir($this->tmp)) {
            exec('rm -rf ' . escapeshellarg($this->tmp));
        }
    }

    private function stub(string $name, string $body): void
    {
        file_put_contents($this->tmp . '/bin/' . $name, $body . "\n");
        chmod($this->tmp . '/bin/' . $name, 0755);
    }

    private function runEntrypoint(int $prepareRc): void
    {
        $env = self::SENTINELS + [
            'PATH' => $this->tmp . '/bin:/usr/bin:/bin',
            'FP_STUB_DIR' => $this->tmp . '/out',
            'FP_PREPARE_RC' => (string) $prepareRc,
            'FUNNYPOT_IDENTITY_RUNTIME_DIR' => $this->tmp . '/runtime',
            'FUNNYPOT_NGINX_CONFD' => $this->tmp . '/confd',
            'FUNNYPOT_PROTOCOLS' => '1',
        ];
        // Files, not pipes: the backgrounded listener/worker loops inherit stdout/stderr and would
        // otherwise hold a pipe open past the main process.
        $p = proc_open(['/bin/sh', dirname(__DIR__, 3) . '/demo/entrypoint.sh'], [
            0 => ['file', '/dev/null', 'r'],
            1 => ['file', $this->tmp . '/out/stdout', 'w'],
            2 => ['file', $this->tmp . '/out/stderr', 'w'],
        ], $pipes, $this->tmp, $env);
        self::assertIsResource($p);
        $deadline = microtime(true) + 20;
        while (microtime(true) < $deadline) {
            $st = proc_get_status($p);
            if (!$st['running']) {
                break;
            }
            usleep(50000);
        }
        $st = proc_get_status($p);
        if ($st['running']) {
            proc_terminate($p, 9);
            self::fail('entrypoint did not finish: ' . (string) file_get_contents($this->tmp . '/out/stderr'));
        }
        proc_close($p);
        usleep(300000); // let the last stubbed children flush their env dumps
    }

    /** @return list<string> */
    private function calls(): array
    {
        $log = $this->tmp . '/out/calls.log';

        return is_file($log) ? array_values(array_filter(explode("\n", (string) file_get_contents($log)))) : [];
    }

    public function test_prepare_runs_first_and_a_failure_starts_nothing(): void
    {
        $this->runEntrypoint(1);
        $calls = $this->calls();
        self::assertSame(['php /app/bin/funnypot identity:prepare'], $calls, 'prepare is the first and, on failure, the ONLY command');
        self::assertFileDoesNotExist($this->tmp . '/out/env.php-fpm');
        self::assertFileDoesNotExist($this->tmp . '/out/env.nginx');
        self::assertSame([], glob($this->tmp . '/out/env.listen.*') ?: [], 'no listener spawned');
        self::assertSame([], glob($this->tmp . '/out/env.worker.*') ?: [], 'no worker spawned');
        $src = (string) file_get_contents(dirname(__DIR__, 3) . '/demo/entrypoint.sh');
        self::assertDoesNotMatchRegularExpression('/identity:prepare[^\n]*\|\|\s*true/', $src, 'prepare must never be guarded by || true');
        self::assertMatchesRegularExpression('/^set -e/m', $src);
    }

    public function test_success_scrubs_every_identity_input_from_every_child(): void
    {
        $this->runEntrypoint(0);
        $calls = $this->calls();
        self::assertSame('php /app/bin/funnypot identity:prepare', $calls[0] ?? null, 'prepare first');
        self::assertContains('php-fpm --daemonize', $calls);
        self::assertGreaterThan(array_search('php /app/bin/funnypot identity:prepare', $calls, true), array_search('php-fpm --daemonize', $calls, true), 'php-fpm only after prepare');
        self::assertContains('nginx -g daemon off;', $calls);
        $listeners = glob($this->tmp . '/out/env.listen.*') ?: [];
        self::assertGreaterThanOrEqual(30, count($listeners), 'listeners were spawned');
        $workers = glob($this->tmp . '/out/env.worker.*') ?: [];
        self::assertNotEmpty($workers);

        // The prepare step itself must have SEEN the inputs (the scrub happens after it, not before).
        $prepareEnv = (string) file_get_contents($this->tmp . '/out/env.prepare');
        foreach (self::SENTINELS as $name => $value) {
            self::assertStringContainsString("{$name}={$value}", $prepareEnv, "prepare must receive {$name}");
        }

        $children = array_merge([$this->tmp . '/out/env.php-fpm', $this->tmp . '/out/env.nginx'], $listeners, $workers);
        foreach ($children as $file) {
            $env = (string) file_get_contents($file);
            foreach (self::SENTINELS as $name => $value) {
                self::assertStringNotContainsString($value, $env, basename($file) . " still carries the {$name} VALUE");
                self::assertDoesNotMatchRegularExpression('/^' . preg_quote($name, '/') . '=/m', $env, basename($file) . " still carries {$name}");
            }
            self::assertStringContainsString('FUNNYPOT_IDENTITY_RUNTIME_DIR=' . $this->tmp . '/runtime', $env, basename($file) . ' must keep the runtime dir path');
        }
        self::assertSame(array_keys(self::SENTINELS), IdentityInputs::SCRUBBED, 'the shell unset list and the PHP scrub list are the same seven');
        $src = (string) file_get_contents(dirname(__DIR__, 3) . '/demo/entrypoint.sh');
        foreach (array_keys(self::SENTINELS) as $name) {
            self::assertMatchesRegularExpression('/^unset [^\n]*\b' . preg_quote($name, '/') . '\b/m', $src, "entrypoint unsets {$name}");
        }

        // Linux extra: the kernel's own view of the php-fpm environment agrees.
        if (is_file($this->tmp . '/out/environ.php-fpm')) {
            $environ = (string) file_get_contents($this->tmp . '/out/environ.php-fpm');
            foreach (self::SENTINELS as $value) {
                self::assertStringNotContainsString($value, $environ);
            }
        }
    }
}
