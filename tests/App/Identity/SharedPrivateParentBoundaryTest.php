<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Identity;

use Funnypot\App\Identity\IdentityBootstrapException;
use Funnypot\App\Identity\IdentityPreparationResult;
use PHPUnit\Framework\TestCase;

final class SharedPrivateParentBoundaryTest extends TestCase
{
    private string $dir = '';

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/fp-shared-parent-' . bin2hex(random_bytes(6));
        mkdir($this->dir, 0700);
    }

    protected function tearDown(): void
    {
        $this->removeFixture($this->dir);
    }

    public function testIdentityRerunAcceptsProductionTraverseOnlySharedParent(): void
    {
        $first = PreparedIdentityFixture::prepare($this->dir)['result'];
        $first->close();
        chmod($this->dir . '/.funnypot', 0711);

        $second = PreparedIdentityFixture::prepare($this->dir)['result'];
        self::assertSame(IdentityPreparationResult::SOURCE_EXPLICIT_ENV, $second->sourceClass);
        self::assertCount(7, $second->sources());
        $second->close();
    }

    public function testIdentityRerunRejectsReadableOrWritableSharedParent(): void
    {
        foreach ([0755, 0733] as $mode) {
            $root = $this->dir . '/' . sprintf('%04o', $mode);
            mkdir($root, 0700);
            $first = PreparedIdentityFixture::prepare($root)['result'];
            $first->close();
            chmod($root . '/.funnypot', $mode);
            $this->expectIdentityFailure($root, 'private-dir-unsafe');
        }
    }

    public function testIdentityRerunRejectsSymlinkedPrivateComponent(): void
    {
        $first = PreparedIdentityFixture::prepare($this->dir)['result'];
        $first->close();
        rename($this->dir . '/.funnypot/identity', $this->dir . '/identity-real');
        symlink($this->dir . '/identity-real', $this->dir . '/.funnypot/identity');

        $this->expectIdentityFailure($this->dir, 'private-dir-unsafe');
    }

    private function expectIdentityFailure(string $root, string $code): void
    {
        try {
            PreparedIdentityFixture::prepare($root);
        } catch (IdentityBootstrapException $e) {
            self::assertSame($code, $e->errorCode());

            return;
        }
        self::fail('expected identity bootstrap failure ' . $code);
    }

    private function removeFixture(string $path): void
    {
        $st = @lstat($path);
        if (!is_array($st)) { return; }
        if ((((int) $st['mode']) & 0170000) !== 0040000) { @unlink($path); return; }
        @chmod($path, 0700);
        $names = @scandir($path);
        if (is_array($names)) {
            foreach ($names as $name) {
                if ($name !== '.' && $name !== '..') { $this->removeFixture($path . '/' . $name); }
            }
        }
        @rmdir($path);
    }
}
