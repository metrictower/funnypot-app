<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Identity;

use Funnypot\App\Identity\IdentityBootstrapException;
use Funnypot\App\Identity\IdentityFileOps;
use Funnypot\App\Identity\SourceOpenAttestation;
use Funnypot\App\Identity\SourceOpener;
use PHPUnit\Framework\TestCase;

/**
 * The `direct-nofollow/v1` chain in isolation: component-wise lstat, a final lstat, an fstat that
 * must REPRODUCE the lstat facts (dev/ino/mode/uid/gid/nlink), a bounded read, and a second fstat
 * that must still agree. Each link is broken on its own here so a future "capture but do not
 * compare" regression is caught by a test, not only by the master store's separate checks.
 */
final class SourceOpenerTest extends TestCase
{
    private string $base = '';

    protected function setUp(): void
    {
        $this->base = (string) realpath(sys_get_temp_dir()) . '/fp_opener_' . bin2hex(random_bytes(5));
        mkdir($this->base . '/tree/inner', 0755, true);
        file_put_contents($this->base . '/tree/inner/file.txt', "payload\n");
        chmod($this->base . '/tree/inner/file.txt', 0644);
    }

    protected function tearDown(): void
    {
        if ($this->base !== '' && is_dir($this->base)) {
            exec('chmod -R u+rwX ' . escapeshellarg($this->base) . ' && rm -rf ' . escapeshellarg($this->base));
        }
    }

    private function expectCode(string $code, callable $fn): void
    {
        try {
            $fn();
        } catch (IdentityBootstrapException $e) {
            self::assertSame($code, $e->errorCode());

            return;
        }
        self::fail("expected {$code}");
    }

    private function open(?IdentityFileOps $ops = null, int $dirMask = SourceOpener::MODE_NO_GO_WRITE, int $fileMask = SourceOpener::MODE_NO_GO_WRITE)
    {
        return (new SourceOpener($ops ?? new IdentityFileOps()))->openDirect($this->base, ['tree', 'inner', 'file.txt'], 'src', 4096, $dirMask, $fileMask);
    }

    public function test_happy_path_attests_the_opened_inode_and_keeps_the_handle_open(): void
    {
        $src = $this->open();
        self::assertSame("payload\n", $src->bytes);
        self::assertSame(SourceOpenAttestation::DIRECT_NOFOLLOW, $src->attestation->id);
        self::assertTrue($src->attestation->isRegularFile());
        self::assertSame(1, $src->attestation->nlink);
        self::assertSame(hash('sha256', "payload\n"), $src->sha256());
        self::assertIsResource($src->handle);
        self::assertTrue($src->attestation->matches((array) fstat($src->handle)));
        $st = lstat($this->base . '/tree/inner/file.txt');
        self::assertSame((int) $st['ino'], $src->attestation->ino);
        self::assertSame((int) $st['dev'], $src->attestation->dev);
        fclose($src->handle);
    }

    public function test_fstat_that_does_not_reproduce_the_lstat_facts_fails(): void
    {
        // The lstat→open window: what was opened is not the inode that was validated. Only the FIRST
        // fstat lies (the post-read fstat is honest), so this fails only if the first compare exists.
        $ops = new class () extends IdentityFileOps {
            private int $calls = 0;

            public function fstat($h)
            {
                $st = parent::fstat($h);
                if (is_array($st) && ++$this->calls === 1) {
                    $st['ino'] = (int) $st['ino'] + 1;
                }

                return $st;
            }
        };
        $this->expectCode('src-changed', fn () => $this->open($ops));
    }

    public function test_mutation_during_read_fails(): void
    {
        // First fstat agrees, the post-read fstat reports a different size/identity.
        $ops = new class () extends IdentityFileOps {
            private int $calls = 0;

            public function fstat($h)
            {
                $st = parent::fstat($h);
                if (is_array($st) && ++$this->calls === 2) {
                    $st['nlink'] = (int) $st['nlink'] + 1;
                }

                return $st;
            }
        };
        $this->expectCode('src-changed', fn () => $this->open($ops));
    }

    public function test_symlink_components_and_finals_are_never_followed(): void
    {
        rename($this->base . '/tree/inner', $this->base . '/elsewhere');
        symlink($this->base . '/elsewhere', $this->base . '/tree/inner');
        $this->expectCode('src-component-unsafe', fn () => $this->open());
        unlink($this->base . '/tree/inner');
        mkdir($this->base . '/tree/inner', 0755);
        symlink($this->base . '/elsewhere/file.txt', $this->base . '/tree/inner/file.txt');
        $this->expectCode('src-unsafe', fn () => $this->open());
    }

    public function test_group_or_other_writable_component_or_file_fails(): void
    {
        chmod($this->base . '/tree/inner', 0777);
        $this->expectCode('src-component-unsafe', fn () => $this->open());
        chmod($this->base . '/tree/inner', 0755);
        chmod($this->base . '/tree/inner/file.txt', 0666);
        $this->expectCode('src-unsafe', fn () => $this->open());
        chmod($this->base . '/tree/inner/file.txt', 0644);
        // The private mask additionally forbids any group/other READ.
        $this->expectCode('src-unsafe', fn () => $this->open(null, SourceOpener::MODE_NO_GO_WRITE, SourceOpener::MODE_PRIVATE));
    }

    public function test_extra_hard_link_missing_file_oversize_and_bad_segments_fail(): void
    {
        link($this->base . '/tree/inner/file.txt', $this->base . '/tree/inner/twin.txt');
        $this->expectCode('src-link-count', fn () => $this->open());
        unlink($this->base . '/tree/inner/twin.txt');

        file_put_contents($this->base . '/tree/inner/file.txt', str_repeat('x', 5000));
        $this->expectCode('src-read', fn () => $this->open());
        file_put_contents($this->base . '/tree/inner/file.txt', "payload\n");

        $opener = new SourceOpener(new IdentityFileOps());
        $this->expectCode('src-path', static fn () => $opener->openDirect('/', [], 'src', 10, 0, 0));
        $this->expectCode('src-path', fn () => $opener->openDirect($this->base, ['tree', '..', 'file.txt'], 'src', 10, 0, 0));
        $this->expectCode('src-path', fn () => $opener->openDirect($this->base, ['tree/inner', 'file.txt'], 'src', 10, 0, 0));
        unlink($this->base . '/tree/inner/file.txt');
        $this->expectCode('src-missing', fn () => $this->open());
    }

    public function test_canonical_path_requirement(): void
    {
        $opener = new SourceOpener(new IdentityFileOps());
        $src = $opener->openCanonicalPath($this->base . '/tree/inner/file.txt', 'src', 4096, SourceOpener::MODE_NO_GO_WRITE);
        self::assertSame("payload\n", $src->bytes);
        fclose($src->handle);
        symlink($this->base . '/tree', $this->base . '/link');
        $this->expectCode('src-path', fn () => $opener->openCanonicalPath($this->base . '/link/inner/file.txt', 'src', 4096, SourceOpener::MODE_NO_GO_WRITE));
        $this->expectCode('src-path', fn () => $opener->openCanonicalPath('relative/file.txt', 'src', 4096, SourceOpener::MODE_NO_GO_WRITE));
        $this->expectCode('src-path', fn () => $opener->openCanonicalPath($this->base . '/tree/inner/../inner/file.txt', 'src', 4096, SourceOpener::MODE_NO_GO_WRITE));
    }

    public function test_accepted_owners_are_root_and_the_effective_uid(): void
    {
        $opener = new SourceOpener(new IdentityFileOps());
        self::assertSame(array_values(array_unique([0, posix_geteuid()])), $opener->acceptedOwners());
        $foreign = new class () extends IdentityFileOps {
            public function euid(): int
            {
                return 4242; // a different effective uid: files owned by the test user are no longer ours
            }
        };
        self::assertSame([0, 4242], (new SourceOpener($foreign))->acceptedOwners());
        $this->expectCode('src-component-unsafe', fn () => $this->open($foreign));
    }
}
