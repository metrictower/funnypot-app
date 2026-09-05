<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Identity;

use Funnypot\App\Identity\InstallSecretStore;
use PHPUnit\Framework\TestCase;

/**
 * bin/funnypot identity:prepare / identity:status: no secret option is ever accepted, and neither
 * stdout nor stderr carries the master, a derived key, the raw override, the commitment or a
 * private path — on success and on every fault.
 */
final class IdentityCliTest extends TestCase
{
    private string $data = '';

    protected function setUp(): void
    {
        if (!function_exists('proc_open')) {
            self::markTestSkipped('proc_open disabled');
        }
        $this->data = (string) realpath(sys_get_temp_dir()) . '/fp_cli_' . bin2hex(random_bytes(5));
        mkdir($this->data, 0777);
    }

    protected function tearDown(): void
    {
        if ($this->data !== '' && is_dir($this->data)) {
            exec('chmod -R u+rwX ' . escapeshellarg($this->data) . ' && rm -rf ' . escapeshellarg($this->data));
        }
    }

    /**
     * @param list<string>         $args
     * @param array<string,string> $extraEnv
     * @return array{0:int,1:string,2:string}
     */
    private function runCli(array $args, array $extraEnv = []): array
    {
        $env = $extraEnv + [
            'PATH' => (string) (getenv('PATH') ?: '/usr/bin:/bin'),
            'FUNNYPOT_DB' => $this->data . '/funnypot.sqlite',
            'FUNNYPOT_IDENTITY_RUNTIME_DIR' => $this->data . '/runtime',
        ];
        foreach (['PHPRC', 'PHP_INI_SCAN_DIR'] as $k) {
            $v = getenv($k);
            if ($v !== false && $v !== '') {
                $env[$k] = $v;
            }
        }
        $pipes = [];
        $p = proc_open([PHP_BINARY, dirname(__DIR__, 3) . '/bin/funnypot', ...$args], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $this->data, $env);
        self::assertIsResource($p);
        $out = (string) stream_get_contents($pipes[1]);
        $err = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        return [proc_close($p), $out, $err];
    }

    /** @return list<string> */
    private function sentinels(string $master, string $override): array
    {
        $d = \Funnypot\App\Identity\IdentityKeyDeriver::fromMaster($master);

        return [
            sodium_bin2base64($master, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING),
            bin2hex($master),
            $override,
            $d->keysetCommitment(),
            \Funnypot\App\Identity\IdentityKeyDeriver::encodeKey($d->coreRenderSalt()),
            \Funnypot\App\Identity\IdentityKeyDeriver::encodeKey($d->shellFilesystemKey()),
            \Funnypot\App\Identity\IdentityKeyDeriver::encodeKey($d->postExploitStateKey()),
            $this->data,
            '.funnypot/identity',
        ];
    }

    public function test_rejects_any_option_including_a_secret_shaped_one(): void
    {
        foreach ([['identity:prepare', '--secret=abc'], ['identity:prepare', '--install-secret-file=/x'], ['identity:status', '--verbose'], ['identity:prepare', 'extra']] as $args) {
            [$rc, $out, $err] = $this->runCli($args);
            self::assertSame(2, $rc, implode(' ', $args));
            self::assertStringContainsString('takes no options', $err);
            self::assertStringNotContainsString('abc', $err);
            self::assertSame('', $out);
        }
        self::assertFileDoesNotExist($this->data . '/.funnypot', 'a rejected invocation prepares nothing');
    }

    public function test_prepare_and_status_succeed_without_printing_a_secret(): void
    {
        $master = hash('sha256', 'cli-sentinel-master', true);
        $override = 'cli-sentinel-override-persona-9f2c';
        [$rc, $out, $err] = $this->runCli(['identity:prepare'], ['FUNNYPOT_INSTALL_SECRET' => InstallSecretStore::serialize($master), 'FUNNYPOT_PERSONA_SEED' => $override]);
        self::assertSame(0, $rc, $err);
        self::assertStringContainsString('identity: prepared (source=explicit-env, persona=override, tls=generated, identity=fpph1_', $out);
        foreach ($this->sentinels($master, $override) as $s) {
            self::assertStringNotContainsString($s, $out . $err, 'prepare output leaked a sentinel');
        }

        [$rc, $out, $err] = $this->runCli(['identity:status'], ['FUNNYPOT_INSTALL_SECRET' => InstallSecretStore::serialize($master), 'FUNNYPOT_PERSONA_SEED' => $override]);
        self::assertSame(0, $rc, $err);
        self::assertStringContainsString('identity: ready', $out);
        self::assertStringContainsString('source: explicit-env', $out);
        self::assertStringContainsString('check http: ok', $out);
        self::assertStringContainsString('check post-exploit-state: ok', $out);
        self::assertStringContainsString('public_identity: fpph1_', $out);
        foreach ($this->sentinels($master, $override) as $s) {
            self::assertStringNotContainsString($s, $out . $err, 'status output leaked a sentinel');
        }
        self::assertStringNotContainsString('fpkc1_', $out . $err, 'the commitment is never printed');

        // Status is honest once the runtime is gone.
        exec('rm -rf ' . escapeshellarg($this->data . '/runtime'));
        [$rc, $out] = $this->runCli(['identity:status'], ['FUNNYPOT_INSTALL_SECRET' => InstallSecretStore::serialize($master), 'FUNNYPOT_PERSONA_SEED' => $override]);
        self::assertSame(1, $rc);
        self::assertStringContainsString('NOT ready', $out);
    }

    public function test_faults_print_only_a_code(): void
    {
        $override = 'cli-fault-override-persona-1a2b';
        [$rc, $out, $err] = $this->runCli(['identity:prepare'], ['FUNNYPOT_INSTALL_SECRET' => 'funnypot-install-secret-v1:not-really-a-master-value-at-all-xx', 'FUNNYPOT_PERSONA_SEED' => $override]);
        self::assertSame(1, $rc);
        self::assertSame('', $out);
        self::assertStringContainsString('identity:prepare failed: install-secret-env-malformed (remedy: config)', $err);
        self::assertStringNotContainsString('not-really-a-master', $err);
        self::assertStringNotContainsString($override, $err);
        self::assertStringNotContainsString($this->data, $err);
        self::assertStringNotContainsString('.php', $err, 'no source location');
        self::assertFileDoesNotExist($this->data . '/runtime', 'no runtime is published on failure');

        // Storage failure class: an unsafe (group/other-accessible) private directory. The failed
        // run above already created it 0700 before the master was parsed; loosen it.
        chmod($this->data . '/.funnypot', 0755);
        [$rc, , $err] = $this->runCli(['identity:prepare']);
        self::assertSame(1, $rc);
        self::assertStringContainsString('private-dir-unsafe (remedy: storage)', $err);
        self::assertStringNotContainsString($this->data, $err);
    }

    public function test_a_bad_path_input_fails_with_a_code_never_an_uncaught_trace(): void
    {
        // Path inputs are validated while the preparer is constructed, before either command runs;
        // that failure must be reported exactly like any other — a code, never a PHP trace (which
        // would print the offending value and a source location).
        foreach ([
            ['identity:status', ['FUNNYPOT_IDENTITY_RUNTIME_DIR' => 'relative/run-dir'], 'runtime-root-invalid'],
            ['identity:prepare', ['FUNNYPOT_IDENTITY_RUNTIME_DIR' => '/run/../escaped-dir'], 'runtime-root-invalid'],
            ['identity:prepare', ['FUNNYPOT_DB' => 'relative-hits.sqlite'], 'storage-root-invalid'],
        ] as [$cmd, $env, $code]) {
            [$rc, $out, $err] = $this->runCli([$cmd], $env);
            self::assertSame(2, $rc, "{$cmd} {$code}");
            self::assertSame('', $out, "{$cmd} {$code}");
            self::assertStringContainsString("{$cmd} failed: {$code} (remedy: config)", $err);
            self::assertStringNotContainsString('Stack trace', $err);
            self::assertStringNotContainsString('.php', $err, 'no source location');
            foreach ($env as $value) {
                self::assertStringNotContainsString($value, $err, 'the offending value is never echoed');
            }
        }
        self::assertFileDoesNotExist($this->data . '/.funnypot', 'a rejected invocation prepares nothing');
        self::assertFileDoesNotExist($this->data . '/runtime');
    }
}
