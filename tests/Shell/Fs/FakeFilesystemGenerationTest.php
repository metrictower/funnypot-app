<?php

declare(strict_types=1);

namespace Funnypot\Tests\Shell\Fs;

use Funnypot\Shell\Fs\Draw;
use Funnypot\Shell\Fs\FakeFilesystem;
use Funnypot\Shell\Fs\PathNotFound;
use PHPUnit\Framework\TestCase;

final class FakeFilesystemGenerationTest extends TestCase
{
    private function fs(): FakeFilesystem
    {
        return new FakeFilesystem(Draw::seed("secret\0host\0dev"), 'developer', 42);
    }

    public function test_scaffold_dirs_always_present_and_nonempty(): void
    {
        $names = array_map(fn ($n) => $n->name, $this->fs()->list('/'));
        foreach (['etc', 'usr', 'var', 'srv', 'tmp', 'root', 'home'] as $d) {
            self::assertContains($d, $names, "root missing scaffold dir $d");
        }
        self::assertNotEmpty($this->fs()->list('/srv/app'));
        self::assertNotEmpty($this->fs()->list('/usr/lib'));
    }

    public function test_listing_is_deterministic(): void
    {
        self::assertEquals($this->fs()->list('/srv/app'), $this->fs()->list('/srv/app'));
    }

    public function test_list_equals_validate(): void
    {
        $fs = $this->fs();
        foreach ($fs->list('/srv') as $node) {
            self::assertTrue($fs->isValidChild('/srv', $node->name));
        }
        self::assertFalse($fs->isValidChild('/srv', 'definitely-not-a-generated-name-zzz'));
        self::assertFalse($fs->isValidChild('/no/such/parent', 'x')); // invalid parent -> false, not throw
    }

    public function test_names_unique_within_dir(): void
    {
        $names = array_map(fn ($n) => $n->name, $this->fs()->list('/usr/lib'));
        self::assertSame(array_values(array_unique($names)), $names);
    }

    public function test_generated_ownership_is_coherent_with_location(): void
    {
        $fs = $this->fs();
        // root's home is root-owned — a uid-1000 file under /root is a generator tell.
        foreach ($fs->list('/root') as $n) {
            self::assertSame(0, $n->uid, "/root/{$n->name} should be root-owned");
            self::assertSame(0, $n->gid, "/root/{$n->name} gid should be root");
        }
        // A user's home is owned by that user (its pinned uid), never by root.
        $homes = $fs->list('/home');
        self::assertNotEmpty($homes);
        $home = $homes[0];
        $homeUid = $home->uid;
        self::assertGreaterThanOrEqual(1000, $homeUid);
        foreach ($fs->list('/home/' . $home->name) as $n) {
            self::assertSame($homeUid, $n->uid, "/home/{$home->name}/{$n->name} should belong to the home owner");
        }
        // /var/www content is the web user (www-data=33 on debian, apache=48 on rhel) — never root/admin.
        foreach ($fs->list('/var/www/html') as $n) {
            self::assertContains($n->uid, [33, 48], "/var/www/html/{$n->name} should be the web user");
        }
    }

    public function test_invalid_path_throws(): void
    {
        $this->expectException(PathNotFound::class);
        $this->fs()->list('/srv/app/nonexistent-zzz/deeper');
    }

    public function test_listing_survives_cache_eviction_unchanged(): void
    {
        // Tiny cache forces FIFO eviction; a re-listed dir MUST regenerate identically (M5 regression:
        // generation is a pure function of the dir seed, not of cache/newcount state).
        $fs = new FakeFilesystem(Draw::seed("evict\0host\0dev"), 'developer', 0, 12, 24, 4);
        $before = $fs->list('/srv/app');
        // list many distinct dirs to blow past the 4-entry cache
        foreach (['/etc', '/usr', '/usr/lib', '/var', '/var/log', '/opt', '/root', '/home', '/usr/share', '/usr/local'] as $d) {
            $fs->list($d);
        }
        self::assertEquals($before, $fs->list('/srv/app'), 'listing changed after cache eviction');
    }

    public function test_pathological_path_is_rejected_not_fatal(): void
    {
        $fs = $this->fs();
        // 20k segments / 40KB path must be refused cheaply (no deep recursion, no OOM) — never a fatal.
        $deep = '/' . str_repeat('a/', 20000);
        self::assertFalse($fs->exists($deep));
        $threw = false;
        try {
            $fs->list($deep);
        } catch (PathNotFound $e) {
            $threw = true;
        }
        self::assertTrue($threw, 'over-deep path should throw PathNotFound, not fatal');
        // very long single segment too
        self::assertFalse($fs->exists('/' . str_repeat('x', 8000)));
    }

    public function test_depth_cap_bottoms_out(): void
    {
        $fs = $this->fs();
        $path = '/srv/app';
        for ($d = 0; $d < 40; $d++) {          // descend REAL generated child dirs
            $sub = null;
            foreach ($fs->list($path) as $n) {
                if ($n->isDir()) {
                    $sub = $n->name;
                    break;
                }
            }
            if ($sub === null) {
                break;
            }
            $path .= '/' . $sub;
        }
        foreach ($fs->list($path) as $n) {     // deepest reachable dir has no further dirs
            self::assertFalse($n->isDir(), 'no dirs past max depth');
        }
    }
}
