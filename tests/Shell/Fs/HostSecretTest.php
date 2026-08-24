<?php

declare(strict_types=1);

namespace Funnypot\Tests\Shell\Fs;

use Funnypot\Shell\Fs\HostSecret;
use PHPUnit\Framework\TestCase;

final class HostSecretTest extends TestCase
{
    private string $dir = '';

    protected function setUp(): void
    {
        putenv('FUNNYPOT_FS_SECRET'); // ensure unset for the file-path tests
        $this->dir = sys_get_temp_dir() . '/fs_secret_test_' . getmypid() . '_' . uniqid();
    }

    protected function tearDown(): void
    {
        putenv('FUNNYPOT_FS_SECRET');
        @unlink($this->dir . '/fs_secret');
        @rmdir($this->dir);
    }

    public function test_generates_persists_and_is_idempotent(): void
    {
        $a = HostSecret::resolve($this->dir);
        self::assertSame(32, strlen($a));
        self::assertFileExists($this->dir . '/fs_secret');
        $b = HostSecret::resolve($this->dir); // second call reads the persisted file
        self::assertSame($a, $b);
    }

    public function test_env_overrides_file(): void
    {
        putenv('FUNNYPOT_FS_SECRET=an-operator-provided-secret');
        self::assertSame('an-operator-provided-secret', HostSecret::resolve($this->dir));
        self::assertFileDoesNotExist($this->dir . '/fs_secret'); // env path writes nothing
    }
}
