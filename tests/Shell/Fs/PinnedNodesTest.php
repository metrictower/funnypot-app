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

    public function test_shadow_is_seeded_not_a_shared_literal(): void
    {
        // B4 regression: the admin shadow line must NOT be a byte-identical constant across installs,
        // and must not be the old '$6$xxxxxxxxxxxxxxxx$0000...' literal.
        $a = new FakeFilesystem(Draw::seed("secretA\0h\0dev"), 'developer');
        $b = new FakeFilesystem(Draw::seed("secretB\0h\0dev"), 'developer');
        $sa = $a->read('/etc/shadow');
        $sb = $b->read('/etc/shadow');
        self::assertNotSame($sa, $sb, 'shadow must vary per host secret');
        self::assertStringNotContainsString('$6$xxxxxxxxxxxxxxxx$', $sa);
        self::assertDoesNotMatchRegularExpression('/\$6\$[^$]{16}\$0{86}/', $sa, 'no all-zero digest');
    }

    public function test_passwd_and_os_release_agree_on_distro_family(): void
    {
        // M1 regression: cross-file consistency — an RHEL os-release must not sit over a Debian passwd.
        for ($i = 0; $i < 30; $i++) {
            $fs = new FakeFilesystem(Draw::seed("distro-seed-{$i}\0h\0ops"), 'ops');
            $os = $fs->read('/etc/os-release');
            $passwd = $fs->read('/etc/passwd');
            if (preg_match('/^ID=(centos|rhel)/m', $os)) {
                self::assertStringContainsString('apache:x:48:48', $passwd, "rhel os-release needs rhel passwd (seed $i)");
                self::assertStringNotContainsString('www-data', $passwd, "seed $i");
            } elseif (preg_match('/^ID=(ubuntu|debian)/m', $os)) {
                self::assertStringContainsString('www-data:x:33:33', $passwd, "debian os-release needs debian passwd (seed $i)");
                self::assertStringNotContainsString('apache:x:48', $passwd, "seed $i");
            }
        }
    }
}
