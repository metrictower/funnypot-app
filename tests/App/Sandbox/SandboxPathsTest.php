<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Sandbox;

use Funnypot\App\Sandbox\Projection\SandboxFileOps;
use Funnypot\App\Sandbox\Projection\SandboxPaths;
use Funnypot\App\Sandbox\Projection\SandboxProjectionException;
use PHPUnit\Framework\TestCase;

final class SandboxPathsTest extends TestCase
{
    private array $temps = [];

    protected function tearDown(): void
    {
        foreach ($this->temps as $temp) { SandboxTestFiles::remove($temp); }
    }

    public function testValidExistingPrivateOverrideOwnsAllFixedNames(): void
    {
        $root = $this->temp();
        $paths = SandboxPaths::fromEnvironment(static fn (string $key) => $key === SandboxPaths::ROOT_ENV ? $root : false);
        $paths->prepareRoot(new SandboxFileOps());
        self::assertSame($root . '/current.json', $paths->current());
        self::assertSame($root . '/previous.json', $paths->previous());
        self::assertDirectoryExists($root . '/generations');
        self::assertSame('0700', substr(sprintf('%o', fileperms($root . '/.ephemeral')), -4));
    }

    /** @dataProvider invalidRoots */
    public function testOverrideRejectsUntrustedRoots(callable $root): void
    {
        $this->expectException(SandboxProjectionException::class);
        SandboxPaths::fromEnvironment(fn (string $key) => $key === SandboxPaths::ROOT_ENV ? $root($this) : false);
    }

    public static function invalidRoots(): iterable
    {
        yield 'relative' => [static fn (): string => 'relative/path'];
        yield 'dotdot' => [static fn (): string => '/tmp/../tmp'];
        yield 'absent' => [static fn (): string => sys_get_temp_dir() . '/fp-absent-' . bin2hex(random_bytes(5))];
        yield 'accessible' => [static fn (self $t): string => $t->temp(0755)];
        yield 'file' => [static function (self $t): string { $dir = $t->temp(); $file = $dir . '/file'; file_put_contents($file, 'x'); return $file; }];
        yield 'symlink' => [static function (self $t): string { $dir = $t->temp(); $link = $dir . '-link'; symlink($dir, $link); $t->temps[] = $link; return $link; }];
    }

    public function temp(int $mode = 0700): string
    {
        $dir = sys_get_temp_dir() . '/fp-sandbox-path-' . bin2hex(random_bytes(6));
        mkdir($dir, $mode);
        chmod($dir, $mode);
        $this->temps[] = $dir;
        return $dir;
    }
}
