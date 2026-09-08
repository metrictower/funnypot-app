<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Sandbox;

use Funnypot\App\Identity\InstallSecretStore;
use PHPUnit\Framework\TestCase;

/** @group heavy */
final class SandboxProjectionProcessHeavyTest extends TestCase
{
    private string $dir = '';
    /** @var array<string,string> */
    private array $env = [];

    protected function setUp(): void
    {
        if (getenv('FUNNYPOT_RUN_SANDBOX_HEAVY') !== '1') { self::markTestSkipped('opt-in multi-process/crash fixture'); }
        $this->dir = sys_get_temp_dir() . '/fp-sandbox-heavy-' . bin2hex(random_bytes(6));
        mkdir($this->dir . '/sandbox', 0700, true);
        mkdir($this->dir . '/storage', 0700);
        $this->env = [
            'PATH' => (string) (getenv('PATH') ?: '/usr/bin:/bin'),
            'FUNNYPOT_DB' => $this->dir . '/storage/funnypot.sqlite',
            'FUNNYPOT_IDENTITY_RUNTIME_DIR' => $this->dir . '/runtime',
            'FUNNYPOT_SANDBOX_ROOT' => $this->dir . '/sandbox',
            'FUNNYPOT_INSTALL_SECRET' => InstallSecretStore::serialize(hash('sha256', 'sandbox-heavy-fixture', true)),
            'FUNNYPOT_PERSONA_SEED' => 'sandbox-heavy-persona-fixture',
        ];
        [$rc, , $err] = $this->run([PHP_BINARY, '-d', 'memory_limit=1G', '-d', 'max_execution_time=120', 'bin/funnypot', 'bootstrap:prepare', '--target=deploy', '--publish=exact']);
        self::assertSame(0, $rc, $err);
    }

    protected function tearDown(): void { SandboxTestFiles::remove($this->dir); }

    public function testTwoPublishersTimeoutThenSerializeWithoutDoubleMint(): void
    {
        $marker = $this->dir . '/lock-held';
        $holder = $this->startPublisher(['FP_SANDBOX_TEST_HOLD_MS' => '3000', 'FP_SANDBOX_TEST_MARKER' => $marker]);
        if (!$this->waitForFile($marker, 5.0)) {
            proc_terminate($holder[0]);
            $this->finish($holder, 2.0);
            self::fail('publisher did not acquire the lock within the wall bound');
        }
        [$loserRc, $loserOut] = $this->runPublisher();
        [$holderRc, $holderOut] = $this->finish($holder, 10.0);
        self::assertSame(1, $loserRc);
        self::assertSame("publication-lock-timeout\n", $loserOut);
        self::assertSame(0, $holderRc);
        self::assertSame("selected-new\n", $holderOut);

        $a = $this->startPublisher();
        $b = $this->startPublisher();
        self::assertSame("unchanged-current\n", $this->finish($a, 10.0)[1]);
        self::assertSame("unchanged-current\n", $this->finish($b, 10.0)[1]);
        self::assertCount(1, glob($this->dir . '/sandbox/generations/[0-9a-f]*', GLOB_ONLYDIR));
    }

    /** @dataProvider crashBoundaries */
    public function testCrashBoundariesRequireFixedPathRecovery(string $stage, string $recovery): void
    {
        [$rc] = $this->runPublisher(['FP_SANDBOX_TEST_CRASH' => $stage]);
        self::assertSame(75, $rc);
        [$recoveryRc, $out] = $this->runPublisher(['FP_SANDBOX_TEST_ACTION' => 'recover']);
        self::assertSame($recovery === 'recovered-selected' ? 0 : 1, $recoveryRc);
        self::assertSame($recovery . "\n", $out);
    }

    public static function crashBoundaries(): iterable
    {
        yield 'before candidate rename' => ['before-candidate-rename', 'nothing-selected'];
        yield 'after candidate rename' => ['after-candidate-rename', 'nothing-selected'];
        yield 'after current rename' => ['after-current-rename', 'recovered-selected'];
    }

    public function testBuiltGenerationUidAccessMatrixFromInsideEachBindSubtree(): void
    {
        if (posix_geteuid() !== 0) { self::markTestSkipped('root-only built-container UID matrix'); }
        [$rc, , $err] = $this->run([PHP_BINARY, '-d', 'memory_limit=1G', '-d', 'max_execution_time=120', 'bin/funnypot', 'sandbox:materialize-views']);
        self::assertSame(0, $rc, $err);
        $selector = json_decode((string) file_get_contents($this->dir . '/sandbox/current.json'), true);
        $views = $this->dir . '/sandbox/generations/' . $selector['generation'] . '/views';
        $cases = [
            ['web', 10007, 10007, 'identity/http.json'],
            ['protocols', 10002, 10002, 'identity/shell.json'],
            ['edge', 10001, 10001, 'tls/funnypot.key'],
            ['post-exploit-state', 10005, 10005, 'identity/post-exploit-state.json'],
        ];
        $probe = '[$u,$g,$p]=array_slice($argv,1);posix_setgid((int)$g);posix_setuid((int)$u);exit(is_string(@file_get_contents($p))?0:1);';
        foreach ($cases as [$owner, $uid, $gid, $file]) {
            [$ownRc] = $this->run([PHP_BINARY, '-d', 'memory_limit=1G', '-d', 'max_execution_time=120', '-r', $probe, (string) $uid, (string) $gid, $file], $views . '/' . $owner);
            self::assertSame(0, $ownRc, $owner . ' must read its private view');
        }
        [$foreignRc] = $this->run([PHP_BINARY, '-d', 'memory_limit=1G', '-d', 'max_execution_time=120', '-r', $probe, '10007', '10007', 'identity/shell.json'], $views . '/protocols');
        self::assertSame(1, $foreignRc, 'web cannot read the protocols bind subtree');
    }

    /** @param array<string,string> $extra @return array{int,string,string} */
    private function runPublisher(array $extra = []): array { return $this->finish($this->startPublisher($extra), 10.0); }

    /** @param array<string,string> $extra @return array{resource,array<int,resource>} */
    private function startPublisher(array $extra = []): array
    {
        $pipes = [];
        $process = proc_open(
            [PHP_BINARY, '-d', 'memory_limit=1G', '-d', 'max_execution_time=120', 'tests/Fixtures/sandbox-publisher.php'],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, dirname(__DIR__, 3), $this->env + $extra,
        );
        self::assertIsResource($process);
        return [$process, $pipes];
    }

    /** @param array{resource,array<int,resource>} $child @return array{int,string,string} */
    private function finish(array $child, float $seconds): array
    {
        [$process, $pipes] = $child;
        stream_set_blocking($pipes[1], false); stream_set_blocking($pipes[2], false);
        $out = ''; $err = ''; $deadline = microtime(true) + $seconds;
        do {
            $out .= (string) stream_get_contents($pipes[1]); $err .= (string) stream_get_contents($pipes[2]);
            $status = proc_get_status($process);
            if (!$status['running']) { break; }
            if (microtime(true) >= $deadline) { proc_terminate($process); self::fail('heavy child exceeded wall bound'); }
            usleep(10000);
        } while (true);
        $out .= (string) stream_get_contents($pipes[1]); $err .= (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]); fclose($pipes[2]);
        $closed = proc_close($process);
        $rc = $status['exitcode'] >= 0 ? $status['exitcode'] : $closed;
        return [$rc, $out, $err];
    }

    /** @return array{int,string,string} */
    private function run(array $command, ?string $cwd = null): array
    {
        $pipes = [];
        $process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $cwd ?? dirname(__DIR__, 3), $this->env);
        self::assertIsResource($process);
        return $this->finish([$process, $pipes], 15.0);
    }

    private function waitForFile(string $path, float $seconds): bool
    {
        $deadline = microtime(true) + $seconds;
        while (!is_file($path) && microtime(true) < $deadline) { usleep(10000); }
        return is_file($path);
    }
}
