<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Sandbox;

use Funnypot\App\Identity\InstallSecretStore;
use Funnypot\App\Service\CanonicalJson;
use PHPUnit\Framework\TestCase;

final class SandboxCliTest extends TestCase
{
    private string $dir = '';
    /** @var array<string,string> */
    private array $env = [];

    protected function setUp(): void
    {
        if (!function_exists('proc_open')) { self::markTestSkipped('proc_open disabled'); }
        $this->dir = sys_get_temp_dir() . '/fp-sandbox-cli-' . bin2hex(random_bytes(6));
        mkdir($this->dir . '/sandbox', 0700, true);
        mkdir($this->dir . '/storage', 0700);
        chmod($this->dir . '/sandbox', 0700);
        $this->env = [
            'PATH' => (string) (getenv('PATH') ?: '/usr/bin:/bin'),
            'FUNNYPOT_DB' => $this->dir . '/storage/funnypot.sqlite',
            'FUNNYPOT_IDENTITY_RUNTIME_DIR' => $this->dir . '/runtime',
            'FUNNYPOT_SANDBOX_ROOT' => $this->dir . '/sandbox',
            'FUNNYPOT_INSTALL_SECRET' => InstallSecretStore::serialize(hash('sha256', 'sandbox-cli-fixture', true)),
            'FUNNYPOT_PERSONA_SEED' => 'sandbox-cli-persona-fixture',
        ];
    }

    protected function tearDown(): void
    {
        SandboxTestFiles::remove($this->dir);
    }

    public function testRealCommandsPrepareMaterializeStatusAndShortCircuitInOneProcessEach(): void
    {
        [$rc, , $err] = $this->runCli(['bootstrap:prepare', '--target=deploy', '--publish=exact']);
        self::assertSame(0, $rc, $err);
        [$rc, $identityOut, $err] = $this->runCli(['identity:prepare']);
        self::assertSame(0, $rc, $identityOut . $err);
        [$rc, $out, $err] = $this->runCli(['sandbox:materialize-views']);
        self::assertSame(0, $rc, $out . $err);
        self::assertStringContainsString('sandbox: selected-new generation=', $out);
        $selector = (string) file_get_contents($this->dir . '/sandbox/current.json');

        [$rc, $out, $err] = $this->runCli(['sandbox:materialize-views']);
        self::assertSame(0, $rc, $err);
        self::assertStringContainsString('sandbox: unchanged-current generation=', $out);
        self::assertSame($selector, (string) file_get_contents($this->dir . '/sandbox/current.json'));

        [$rc, $out, $err] = $this->runCli(['sandbox:projection-status', '--json']);
        self::assertSame(posix_geteuid() === 0 ? 0 : 1, $rc, $err);
        $status = json_decode($out, true);
        self::assertIsArray($status);
        self::assertSame(posix_geteuid() === 0, $status['ready']);
        self::assertArrayNotHasKey('identity_keyset_commitment', $status);
        self::assertStringNotContainsString('fpkc1_', $out . $err);
        self::assertStringNotContainsString($this->dir, $out . $err);

        [$plainRc, $plain, $plainErr] = $this->runCli(['sandbox:projection-status']);
        self::assertSame(posix_geteuid() === 0 ? 0 : 1, $plainRc, $plainErr);
        self::assertStringContainsString('effective: schema=funnypot-effective-service-exposure/v1 revision=1 generation=', $plain);
        self::assertStringContainsString(' hash=', $plain);
        self::assertStringContainsString(' match=yes', $plain);
    }

    public function testMutatingCommandsRejectEveryArgumentBeforeFilesystemWork(): void
    {
        foreach ([['sandbox:materialize-views', '--out=/tmp/x'], ['sandbox:materialize-views', 'extra'], ['sandbox:rollback-views', '--file=x']] as $args) {
            [$rc, $out, $err] = $this->runCli($args);
            self::assertSame(2, $rc);
            self::assertSame('', $out);
            self::assertStringContainsString('usage:', $err);
        }
        self::assertSame([], array_values(array_diff(scandir($this->dir . '/sandbox'), ['.', '..'])));
    }

    public function testMissingPersistentEffectiveArtifactSelectsNothingWithExactCode(): void
    {
        [$rc, $out, $err] = $this->runCli(['sandbox:materialize-views']);
        self::assertSame(1, $rc, $err);
        self::assertStringContainsString('sandbox: effective-artifact-missing', $out);
        self::assertFileDoesNotExist($this->dir . '/sandbox/current.json');
    }

    public function testCorruptEffectiveAndIdentityFaultEachPreserveExactPriorSelector(): void
    {
        [$rc, , $err] = $this->runCli(['bootstrap:prepare', '--target=deploy', '--publish=exact']);
        self::assertSame(0, $rc, $err);
        [$rc, , $err] = $this->runCli(['sandbox:materialize-views']);
        self::assertSame(0, $rc, $err);
        $selector = (string) file_get_contents($this->dir . '/sandbox/current.json');
        $manifest = $this->dir . '/storage/.funnypot/services/exposure-manifest.json';
        $manifestBytes = (string) file_get_contents($manifest);
        $corrupt = json_decode($manifestBytes, true);
        $corrupt['plan_hash'] = str_repeat('0', 64);
        file_put_contents($manifest, CanonicalJson::encode($corrupt));
        chmod($manifest, 0600);
        [$rc, $out, $err] = $this->runCli(['sandbox:materialize-views']);
        self::assertSame(1, $rc, $err);
        self::assertStringContainsString('effective-artifact-missing', $out);
        self::assertSame($selector, (string) file_get_contents($this->dir . '/sandbox/current.json'));

        file_put_contents($manifest, $manifestBytes);
        chmod($manifest, 0600);
        $identityManifest = $this->dir . '/storage/.funnypot/identity/manifest.json';
        chmod($identityManifest, 0660);
        [$rc, $out, $err] = $this->runCli(['sandbox:materialize-views']);
        self::assertSame(1, $rc, $err);
        self::assertStringContainsString('preserved-prior', $out);
        self::assertSame($selector, (string) file_get_contents($this->dir . '/sandbox/current.json'));
    }

    public function testJsonStatusUnexpectedFailureIsStableParseableAndPathFree(): void
    {
        chmod($this->dir . '/sandbox', 0755);
        [$rc, $out, $err] = $this->runCli(['sandbox:projection-status', '--json']);
        self::assertSame(1, $rc);
        self::assertSame('', $err);
        self::assertSame([
            'code' => 'unexpected', 'entries' => [], 'generation' => null, 'ready' => false,
            'schema' => 'sandbox-projection-selector/v1',
        ], json_decode($out, true));
        self::assertStringNotContainsString($this->dir, $out . $err);
    }

    /** @param list<string> $args @return array{int,string,string} */
    private function runCli(array $args): array
    {
        $pipes = [];
        $process = proc_open([
            PHP_BINARY, '-d', 'memory_limit=1G', '-d', 'max_execution_time=120',
            dirname(__DIR__, 3) . '/bin/funnypot', ...$args,
        ], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $this->dir, $this->env);
        self::assertIsResource($process);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $out = '';
        $err = '';
        $deadline = microtime(true) + 15.0;
        do {
            $out .= (string) stream_get_contents($pipes[1]);
            $err .= (string) stream_get_contents($pipes[2]);
            $status = proc_get_status($process);
            if (!$status['running']) { break; }
            if (microtime(true) >= $deadline) {
                proc_terminate($process);
                self::fail('sandbox CLI child exceeded the 15-second wall bound');
            }
            usleep(10000);
        } while (true);
        $out .= (string) stream_get_contents($pipes[1]);
        $err .= (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]); fclose($pipes[2]);
        $closed = proc_close($process);
        $rc = is_int($status['exitcode'] ?? null) && $status['exitcode'] >= 0 ? $status['exitcode'] : $closed;

        return [$rc, $out, $err];
    }
}
