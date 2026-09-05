<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Identity;

use Funnypot\App\Identity\IdentityPaths;
use PHPUnit\Framework\TestCase;

/**
 * Thirty-two REAL processes prepare the same fresh install at once. Exactly one master may win: every
 * child must report the same public hash, keyset commitment, master inode and TLS fingerprint, the
 * published file must end with link count one and mode 0600, and no attempt's temp may survive. A
 * last-writer-wins or rename-based publication would let two children hold different masters.
 *
 * @group heavy
 */
final class InstallSecretConcurrencyTest extends TestCase
{
    private const CHILDREN = 32;

    private string $base = '';

    protected function setUp(): void
    {
        if (!function_exists('proc_open')) {
            self::markTestSkipped('proc_open disabled');
        }
        $this->base = (string) realpath(sys_get_temp_dir()) . '/fp_conc_' . bin2hex(random_bytes(5));
        mkdir($this->base, 0755);
        mkdir($this->base . '/storage', 0777);
        mkdir($this->base . '/storage/no-legacy-nginx', 0700);
        mkdir($this->base . '/storage/no-letsencrypt', 0700);
    }

    protected function tearDown(): void
    {
        if ($this->base !== '' && is_dir($this->base)) {
            exec('rm -rf ' . escapeshellarg($this->base));
        }
    }

    public function test_thirty_two_concurrent_preparers_converge_on_one_master(): void
    {
        $script = __DIR__ . '/support/prepare-child.php';
        $storage = $this->base . '/storage';
        $procs = [];
        for ($i = 0; $i < self::CHILDREN; $i++) {
            $cmd = [PHP_BINARY, $script, $storage, $this->base . '/runtime-' . $i];
            $pipes = [];
            $p = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $this->base, $this->childEnv());
            self::assertIsResource($p, "child {$i} did not start");
            $procs[] = [$p, $pipes];
        }

        $rows = [];
        foreach ($procs as $i => [$p, $pipes]) {
            $out = (string) stream_get_contents($pipes[1]);
            $err = (string) stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            $rc = proc_close($p);
            self::assertSame(0, $rc, "child {$i} failed (rc={$rc}): {$err}");
            $row = json_decode(trim($out), true);
            self::assertIsArray($row, "child {$i} printed no facts: {$out}");
            $rows[] = $row;
        }

        $hashes = array_unique(array_column($rows, 'hash'));
        $commitments = array_unique(array_column($rows, 'commitment'));
        $inodes = array_unique(array_column($rows, 'ino'));
        $tls = array_unique(array_column($rows, 'tls'));
        self::assertCount(1, $hashes, 'every child must see the same public identity');
        self::assertCount(1, $commitments, 'every child must see the same keyset');
        self::assertCount(1, $inodes, 'every child must read the same master inode');
        self::assertCount(1, $tls, 'every child must select the same generated TLS pair');
        self::assertSame(1, count(array_filter($rows, static fn (array $r): bool => $r['source'] === 'generated')), 'exactly one child creates; the rest read the persisted master');

        $paths = IdentityPaths::forStorage($storage, $this->base . '/runtime-0');
        clearstatcache();
        $st = lstat($paths->masterPath());
        self::assertIsArray($st);
        self::assertSame(1, (int) $st['nlink'], 'final link count must be one');
        self::assertSame(0600, (int) $st['mode'] & 0777);
        $leftovers = array_filter((array) scandir($paths->persistentRoot()), static fn ($n): bool => str_starts_with((string) $n, IdentityPaths::TEMP_PREFIX));
        self::assertSame([], array_values($leftovers), 'no attempt may leave a temp behind');
    }

    /** @return array<string,string> */
    private function childEnv(): array
    {
        $env = ['PATH' => (string) (getenv('PATH') ?: '/usr/bin:/bin')];
        foreach (['PHPRC', 'PHP_INI_SCAN_DIR', 'HOME'] as $k) {
            $v = getenv($k);
            if ($v !== false && $v !== '') {
                $env[$k] = $v;
            }
        }

        return $env;
    }
}
