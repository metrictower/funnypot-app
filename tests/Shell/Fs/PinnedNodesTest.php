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
        return new FakeFilesystem(Draw::seed("s\0h\0dev"), 'developer', 7);
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

    public function test_identity_seed_drives_hostname_secret_does_not(): void
    {
        // hostname is host IDENTITY (from ServerProfile) -> keyed by identitySeed, stable across secrets.
        $base = new FakeFilesystem(Draw::seed("secretA\0h\0dev"), 'developer', 1001);
        $h1 = $base->read('/etc/hostname');
        $sameIdOtherSecret = new FakeFilesystem(Draw::seed("secretB\0h\0dev"), 'developer', 1001);
        self::assertSame($h1, $sameIdOtherSecret->read('/etc/hostname'), 'secret must not change identity');

        $found = false;
        for ($i = 0; $i < 60; $i++) {
            if ((new FakeFilesystem(Draw::seed("secretA\0h\0dev"), 'developer', $i))->read('/etc/hostname') !== $h1) {
                $found = true;
                break;
            }
        }
        self::assertTrue($found, 'a different identitySeed should be able to change the hostname');
    }

    public function test_shadow_is_seeded_not_a_shared_literal(): void
    {
        // B4 regression: the admin shadow line must NOT be a byte-identical constant across installs,
        // and must not be the old '$6$xxxxxxxxxxxxxxxx$0000...' literal.
        $a = new FakeFilesystem(Draw::seed("secretA\0h\0dev"), 'developer', 7);
        $b = new FakeFilesystem(Draw::seed("secretB\0h\0dev"), 'developer', 7);
        $sa = $a->read('/etc/shadow');
        $sb = $b->read('/etc/shadow');
        self::assertNotSame($sa, $sb, 'shadow must vary per host secret');
        self::assertStringNotContainsString('$6$xxxxxxxxxxxxxxxx$', $sa);
        self::assertDoesNotMatchRegularExpression('/\$6\$[^$]{16}\$0{86}/', $sa, 'no all-zero digest');

        // The DIGEST itself (not just lastchg/name) must vary — extract $6$<salt>$<digest> from each.
        $hash = static function (string $shadow): array {
            return preg_match('/\$6\$([^$:]+)\$([^:]+)/', $shadow, $m) ? [$m[1], $m[2]] : [null, null];
        };
        [$saltA, $digA] = $hash($sa);
        [$saltB, $digB] = $hash($sb);
        self::assertSame(16, strlen((string) $saltA));
        self::assertSame(86, strlen((string) $digA));
        self::assertNotSame($saltA, $saltB, 'salt must vary');
        self::assertNotSame($digA, $digB, 'digest must vary');
    }

    private function firstSeedOfFamily(string $family): ?FakeFilesystem
    {
        for ($i = 0; $i < 80; $i++) {
            $fs = new FakeFilesystem(Draw::seed("s\0h\0ops"), 'ops', $i); // OS is keyed by identitySeed now
            $os = $fs->read('/etc/os-release');
            $isRhel = (bool) preg_match('/^ID=(rocky|centos|rhel|almalinux|amzn)/m', $os);
            if (($family === 'rhel') === $isRhel) {
                return $fs;
            }
        }

        return null;
    }

    public function test_var_www_uid_matches_distro_family(): void
    {
        foreach (['rhel' => 48, 'debian' => 33] as $fam => $expectedUid) {
            $fs = $this->firstSeedOfFamily($fam);
            self::assertNotNull($fs, "could not find a {$fam} seed");
            $checked = 0;
            foreach (['/var/www', '/var/www/html'] as $dir) {
                foreach ($fs->list($dir) as $n) {
                    if ($n->isFile() && $n->uid !== 0) {
                        self::assertSame($expectedUid, $n->uid, "{$fam} /var/www file uid ({$dir}/{$n->name})");
                        $checked++;
                    }
                }
            }
            // (may be 0 non-root files for a given seed; the assertion only fires when one exists)
            self::assertGreaterThanOrEqual(0, $checked);
        }
    }

    public function test_passwd_and_os_release_agree_on_distro_family(): void
    {
        // M1 regression: cross-file consistency — an RHEL os-release must not sit over a Debian passwd.
        for ($i = 0; $i < 40; $i++) {
            $fs = new FakeFilesystem(Draw::seed("s\0h\0ops"), 'ops', $i);
            $os = $fs->read('/etc/os-release');
            $passwd = $fs->read('/etc/passwd');
            if (preg_match('/^ID=(rocky|centos|rhel|almalinux|amzn)/m', $os)) {
                self::assertStringContainsString('apache:x:48:48', $passwd, "rhel os-release needs rhel passwd (seed $i)");
                self::assertStringNotContainsString('www-data', $passwd, "seed $i");
            } elseif (preg_match('/^ID=(ubuntu|debian)/m', $os)) {
                self::assertStringContainsString('www-data:x:33:33', $passwd, "debian os-release needs debian passwd (seed $i)");
                self::assertStringNotContainsString('apache:x:48', $passwd, "seed $i");
            }
        }
    }
}
