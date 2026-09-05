<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Identity;

use Funnypot\App\Identity\IdentityBootstrapException;
use Funnypot\App\Identity\IdentityFileOps;
use Funnypot\App\Identity\IdentityPaths;
use Funnypot\App\Identity\InstallSecretStore;
use PHPUnit\Framework\TestCase;

/**
 * The persisted master: exact canonical format, one crash-safe creation, and fail-closed on every
 * unsafe shape. Fault injection goes through the IdentityFileOps seam; nothing here is repaired.
 */
final class InstallSecretStoreTest extends TestCase
{
    private string $base = '';
    private string $storage = '';

    protected function setUp(): void
    {
        $this->base = (string) realpath(sys_get_temp_dir()) . '/fp_store_' . bin2hex(random_bytes(5));
        $this->storage = $this->base . '/storage';
        mkdir($this->base, 0755);
        mkdir($this->storage, 0777);
    }

    protected function tearDown(): void
    {
        if ($this->base !== '' && is_dir($this->base)) {
            exec('chmod -R u+rwX ' . escapeshellarg($this->base) . ' && rm -rf ' . escapeshellarg($this->base));
        }
    }

    private function paths(): IdentityPaths
    {
        return IdentityPaths::forStorage($this->storage, $this->base . '/runtime');
    }

    private function store(?IdentityFileOps $ops = null): InstallSecretStore
    {
        return new InstallSecretStore($this->paths(), $ops ?? new IdentityFileOps());
    }

    private function expectCode(string $code, callable $fn): void
    {
        try {
            $fn();
        } catch (IdentityBootstrapException $e) {
            self::assertSame($code, $e->errorCode());
            self::assertStringNotContainsString($this->base, $e->getMessage(), 'messages never carry a path');

            return;
        }
        self::fail("expected bootstrap failure {$code}");
    }

    // --- canonical format --------------------------------------------------------------------------

    public function test_canonical_round_trip_including_embedded_zero_bytes(): void
    {
        $master = "\x00" . random_bytes(30) . "\x00";
        $line = InstallSecretStore::serialize($master);
        self::assertSame(strlen(InstallSecretStore::PREFIX) + 43 + 1, strlen($line));
        self::assertStringStartsWith('funnypot-install-secret-v1:', $line);
        self::assertStringEndsWith("\n", $line);
        self::assertSame($master, InstallSecretStore::parse($line));
    }

    public function test_all_zero_master_is_rejected_but_individual_zero_bytes_are_not(): void
    {
        $this->expectCode('master-all-zero', static fn () => InstallSecretStore::parse(InstallSecretStore::serialize(str_repeat("\0", 32))));
        self::assertSame(32, strlen(InstallSecretStore::parse(InstallSecretStore::serialize(str_repeat("\0", 31) . "\x01"))));
    }

    /** @dataProvider malformedInputs */
    public function test_malformed_input_is_rejected(string $text): void
    {
        $this->expectCode('master-malformed', static fn () => InstallSecretStore::parse($text));
    }

    /** @return array<string,array{0:string}> */
    public static function malformedInputs(): array
    {
        $good = InstallSecretStore::serialize(random_bytes(32));
        $encoded = substr($good, strlen(InstallSecretStore::PREFIX), 43);

        return [
            'empty' => [''],
            'no newline' => [rtrim($good, "\n")],
            'two lines' => [$good . $good],
            'trailing space' => [rtrim($good, "\n") . " \n"],
            'leading space' => [' ' . $good],
            'crlf' => [rtrim($good, "\n") . "\r\n"],
            'unknown version' => [str_replace('-v1:', '-v2:', $good)],
            'wrong prefix' => ['funnypot-secret-v1:' . $encoded . "\n"],
            'padding char' => [InstallSecretStore::PREFIX . substr($encoded, 0, 42) . "=\n"],
            'standard base64 alphabet' => [InstallSecretStore::PREFIX . str_replace(['-', '_'], ['+', '/'], substr($encoded, 0, 41)) . "+/\n"],
            'too short' => [InstallSecretStore::PREFIX . substr($encoded, 0, 42) . "\n"],
            'too long' => [InstallSecretStore::PREFIX . $encoded . "A\n"],
            'oversized' => [$good . str_repeat('x', 4096)],
        ];
    }

    // --- creation + persistence --------------------------------------------------------------------

    public function test_creates_once_then_reads_the_same_master(): void
    {
        [$m1, $s1] = $this->store()->resolveOrCreate();
        [$m2, $s2] = $this->store()->resolveOrCreate();
        self::assertSame(InstallSecretStore::SOURCE_GENERATED, $s1);
        self::assertSame(InstallSecretStore::SOURCE_PERSISTED, $s2);
        self::assertSame($m1, $m2);
        self::assertSame(32, strlen($m1));

        clearstatcache();
        $st = lstat($this->paths()->masterPath());
        self::assertSame(0600, (int) $st['mode'] & 0777);
        self::assertSame(1, (int) $st['nlink']);
        self::assertSame(0700, (int) lstat($this->paths()->persistentRoot())['mode'] & 0777);
        self::assertSame(0700, (int) lstat($this->paths()->privateRoot())['mode'] & 0777);
        self::assertSame([], $this->tempFiles(), 'no temp left after publication');
        self::assertSame(InstallSecretStore::serialize($m1), file_get_contents($this->paths()->masterPath()));
    }

    public function test_two_roots_yield_different_masters(): void
    {
        [$a] = $this->store()->resolveOrCreate();
        $other = $this->base . '/storage2';
        mkdir($other, 0777);
        [$b] = (new InstallSecretStore(IdentityPaths::forStorage($other, $this->base . '/rt2'), new IdentityFileOps()))->resolveOrCreate();
        self::assertNotSame($a, $b);
    }

    // --- unsafe persisted shapes: never followed, never repaired -----------------------------------

    public function test_symlink_in_place_of_master_fails_and_target_is_untouched(): void
    {
        $this->store()->resolveOrCreate();
        $target = $this->base . '/elsewhere.secret';
        file_put_contents($target, InstallSecretStore::serialize(random_bytes(32)));
        chmod($target, 0600);
        $before = (string) file_get_contents($target);
        unlink($this->paths()->masterPath());
        symlink($target, $this->paths()->masterPath());

        $this->expectCode('master-not-regular', fn () => $this->store()->resolveOrCreate());
        self::assertTrue(is_link($this->paths()->masterPath()), 'the symlink is left in place, not replaced');
        self::assertSame($before, file_get_contents($target));
    }

    public function test_fifo_in_place_of_master_fails(): void
    {
        $this->store()->resolveOrCreate();
        unlink($this->paths()->masterPath());
        self::assertTrue(posix_mkfifo($this->paths()->masterPath(), 0600));
        $this->expectCode('master-not-regular', fn () => $this->store()->resolveOrCreate());
    }

    public function test_wrong_mode_fails_without_repair(): void
    {
        $this->store()->resolveOrCreate();
        chmod($this->paths()->masterPath(), 0644);
        $this->expectCode('master-mode', fn () => $this->store()->resolveOrCreate());
        clearstatcache();
        self::assertSame(0644, (int) lstat($this->paths()->masterPath())['mode'] & 0777, 'never chmod-repaired');
    }

    public function test_truncated_or_malformed_existing_master_fails_and_stays_byte_identical(): void
    {
        $this->store()->resolveOrCreate();
        $p = $this->paths()->masterPath();
        $truncated = substr((string) file_get_contents($p), 0, 40);
        file_put_contents($p, $truncated);
        $this->expectCode('master-malformed', fn () => $this->store()->resolveOrCreate());
        self::assertSame($truncated, file_get_contents($p), 'a bad master is never rewritten');

        file_put_contents($p, InstallSecretStore::serialize(str_repeat("\0", 32)));
        $this->expectCode('master-all-zero', fn () => $this->store()->resolveOrCreate());
    }

    public function test_unsafe_private_directory_is_not_repaired(): void
    {
        $this->store()->resolveOrCreate();
        chmod($this->paths()->persistentRoot(), 0755);
        $this->expectCode('private-dir-unsafe', fn () => $this->store()->resolveOrCreate());
        clearstatcache();
        self::assertSame(0755, (int) lstat($this->paths()->persistentRoot())['mode'] & 0777);
    }

    public function test_symlinked_private_component_is_never_followed(): void
    {
        // A pre-placed .funnypot -> elsewhere link would let the storage owner redirect the identity.
        $elsewhere = $this->base . '/elsewhere';
        mkdir($elsewhere, 0700);
        symlink($elsewhere, $this->storage . '/.funnypot');
        $this->expectCode('private-dir-unsafe', fn () => $this->store()->resolveOrCreate());
        self::assertSame([], array_values(array_diff((array) scandir($elsewhere), ['.', '..'])), 'nothing was created through the link');
    }

    public function test_hard_link_to_a_foreign_name_fails_closed(): void
    {
        $this->store()->resolveOrCreate();
        link($this->paths()->masterPath(), $this->paths()->persistentRoot() . '/install.secret.bak');
        $this->expectCode('master-link-count', fn () => $this->store()->resolveOrCreate());
    }

    public function test_read_only_storage_fails_closed(): void
    {
        $this->store(); // constructs only
        // Pre-create the private dirs owner-only but unwritable so the temp create fails.
        mkdir($this->storage . '/.funnypot', 0700);
        mkdir($this->storage . '/.funnypot/identity', 0700);
        chmod($this->storage . '/.funnypot/identity', 0500);
        $this->expectCode('lock-create', fn () => $this->store()->resolveOrCreate());
    }

    // --- injected faults: crash boundaries and durability ------------------------------------------

    public function test_short_write_fails_before_link_and_leaves_no_master(): void
    {
        $ops = new class () extends IdentityFileOps {
            public function write($h, string $bytes)
            {
                return parent::write($h, substr($bytes, 0, 10));
            }
        };
        $this->expectCode('master-write-short', fn () => $this->store($ops)->resolveOrCreate());
        self::assertFileDoesNotExist($this->paths()->masterPath());
        self::assertSame([], $this->tempFiles(), 'the failed attempt removed its own temp');
    }

    /** @dataProvider durabilityFaults */
    public function test_flush_fsync_link_faults_fail_closed(string $method, string $code): void
    {
        $ops = new class ($method) extends IdentityFileOps {
            public function __construct(private string $failing)
            {
            }

            public function flush($h): bool
            {
                return $this->failing === 'flush' ? false : parent::flush($h);
            }

            public function fsync($h): bool
            {
                if ($this->failing === 'fsync') {
                    return false;
                }
                if ($this->failing === 'dirfsync' && is_resource($h) && stream_get_meta_data($h)['mode'] === 'r') {
                    return false;
                }

                return parent::fsync($h);
            }

            public function link(string $target, string $link): bool
            {
                return $this->failing === 'link' ? false : parent::link($target, $link);
            }
        };
        $this->expectCode($code, fn () => $this->store($ops)->resolveOrCreate());
        self::assertSame([], $this->tempFiles(), 'the failed attempt removed its own temp');
        if ($method !== 'dirfsync') {
            self::assertFileDoesNotExist($this->paths()->masterPath(), 'before link, no master is accepted');
        }
    }

    /** @return array<string,array{0:string,1:string}> */
    public static function durabilityFaults(): array
    {
        return [
            'flush' => ['flush', 'master-flush'],
            'fsync' => ['fsync', 'master-fsync'],
            'link' => ['link', 'master-link'],
            'directory fsync' => ['dirfsync', 'directory-fsync'],
        ];
    }

    public function test_crash_after_link_is_recovered_only_for_the_same_inode_temp(): void
    {
        // Crash boundary: link published, temp unlink "never happened".
        $ops = new class () extends IdentityFileOps {
            public function unlink(string $path): bool
            {
                return false;
            }
        };
        $this->expectCode('master-temp-unlink', fn () => $this->store($ops)->resolveOrCreate());
        $published = (string) file_get_contents($this->paths()->masterPath());
        clearstatcache();
        self::assertSame(2, (int) lstat($this->paths()->masterPath())['nlink'], 'the master exists with its temp still linked');
        self::assertCount(1, $this->tempFiles());

        // A different-inode orphan beside it must be reported, never deleted.
        $orphan = $this->paths()->tempPath('deadbeefdeadbeef');
        file_put_contents($orphan, 'not ours');
        chmod($orphan, 0600);

        $store = $this->store();
        [$master, $source] = $store->resolveOrCreate();
        self::assertSame(InstallSecretStore::SOURCE_PERSISTED, $source);
        self::assertSame(InstallSecretStore::serialize($master), $published, 'the published master is authoritative');
        clearstatcache();
        self::assertSame(1, (int) lstat($this->paths()->masterPath())['nlink'], 'link count returned to one');
        self::assertFileExists($orphan, 'a foreign-inode temp is not ours to delete');
        self::assertContains(InstallSecretStore::WARN_ORPHAN_TEMP, $store->warnings());
    }

    public function test_readback_mismatch_fails(): void
    {
        $other = InstallSecretStore::serialize(random_bytes(32));
        $ops = new class ($other) extends IdentityFileOps {
            public function __construct(private string $other)
            {
            }

            public function readAll($h, int $max)
            {
                return $this->other; // the bytes read back are not the bytes written
            }
        };
        $this->expectCode('master-readback', fn () => $this->store($ops)->resolveOrCreate());
    }

    public function test_lock_timeout_fails_closed(): void
    {
        $ops = new class () extends IdentityFileOps {
            public function flock($h, int $op): bool
            {
                return $op === LOCK_UN;
            }

            public function sleepMs(int $ms): void
            {
            }
        };
        $this->expectCode('lock-timeout', fn () => $this->store($ops)->resolveOrCreate());
        self::assertFileDoesNotExist($this->paths()->masterPath());
    }

    public function test_missing_fsync_capability_fails_at_construction(): void
    {
        $ops = new class () extends IdentityFileOps {
            public function supportsFsync(): bool
            {
                return false;
            }
        };
        $this->expectCode('runtime-fsync-unavailable', fn () => $this->store($ops));
    }

    /** @return list<string> */
    private function tempFiles(): array
    {
        $dir = $this->paths()->persistentRoot();
        if (!is_dir($dir)) {
            return [];
        }

        return array_values(array_filter((array) scandir($dir), static fn ($n): bool => str_starts_with((string) $n, IdentityPaths::TEMP_PREFIX)));
    }
}
