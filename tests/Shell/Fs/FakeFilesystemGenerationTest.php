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
        return new FakeFilesystem(Draw::seed("secret\0host\0dev"), 'developer');
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

    public function test_invalid_path_throws(): void
    {
        $this->expectException(PathNotFound::class);
        $this->fs()->list('/srv/app/nonexistent-zzz/deeper');
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
