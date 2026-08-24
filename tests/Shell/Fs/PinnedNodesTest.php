<?php

declare(strict_types=1);

namespace Funnypot\Tests\Shell\Fs;

use Funnypot\Shell\Fs\Draw;
use Funnypot\Shell\Fs\FakeFilesystem;
use PHPUnit\Framework\TestCase;

final class PinnedNodesTest extends TestCase
{
    private function fs(): FakeFilesystem
    {
        return new FakeFilesystem(Draw::seed("s\0h\0dev"), 'developer');
    }

    public function test_etc_passwd_is_pinned_and_listed(): void
    {
        $fs = $this->fs();
        self::assertTrue($fs->exists('/etc/passwd'));
        self::assertTrue($fs->isValidChild('/etc', 'passwd'));           // list == resolve
        $names = array_map(fn ($n) => $n->name, $fs->list('/etc'));
        self::assertContains('passwd', $names);
        self::assertContains('shadow', $names);
        self::assertContains('os-release', $names);
        self::assertStringContainsString('root:x:0:0:', $fs->read('/etc/passwd'));
    }

    public function test_pinned_content_is_stable_and_size_matches(): void
    {
        $a = $this->fs()->read('/etc/passwd');
        $b = $this->fs()->read('/etc/passwd');
        self::assertSame($a, $b);
        self::assertSame($this->fs()->stat('/etc/passwd')->size, strlen($a));
    }

    public function test_symlink_pinned_with_target(): void
    {
        $link = $this->fs()->stat('/etc/localtime');
        self::assertTrue($link->isLink());
        self::assertSame('/usr/share/zoneinfo/Etc/UTC', $link->target);
    }

    public function test_pinned_varies_by_host_secret(): void
    {
        $one = new FakeFilesystem(Draw::seed("secretA\0h\0dev"), 'developer');
        $two = new FakeFilesystem(Draw::seed("secretB\0h\0dev"), 'developer');
        // hostname + admin user are seeded, so passwd differs across installs.
        self::assertNotSame($one->read('/etc/hostname'), $two->read('/etc/hostname'));
    }
}
