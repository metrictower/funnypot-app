<?php

declare(strict_types=1);

namespace Funnypot\Tests\Shell\Fs;

use Funnypot\Shell\Fs\Draw;
use Funnypot\Shell\Fs\FakeFilesystem;
use Funnypot\Shell\Fs\IsADirectory;
use Funnypot\Shell\Fs\PathNotFound;
use PHPUnit\Framework\TestCase;

final class FakeFilesystemContentTest extends TestCase
{
    private function fs(): FakeFilesystem
    {
        return new FakeFilesystem(Draw::seed("s\0h\0dev"), 'developer');
    }

    public function test_size_matches_content_length_and_is_capped(): void
    {
        $fs = $this->fs();
        $sawFile = false;
        foreach ($fs->list('/srv/app') as $node) {
            if ($node->isFile()) {
                $sawFile = true;
                self::assertLessThanOrEqual(65536, $node->size);
                self::assertSame($node->size, strlen($fs->read('/srv/app/' . $node->name)));
            }
        }
        self::assertTrue($sawFile, '/srv/app should contain at least one file');
    }

    public function test_read_is_deterministic(): void
    {
        $file = null;
        foreach ($this->fs()->list('/srv/app') as $n) {
            if ($n->isFile()) {
                $file = $n->name;
                break;
            }
        }
        self::assertNotNull($file);
        self::assertSame(
            $this->fs()->read('/srv/app/' . $file),
            $this->fs()->read('/srv/app/' . $file)
        );
    }

    public function test_read_on_directory_throws_is_a_directory(): void
    {
        $this->expectException(IsADirectory::class);
        $this->fs()->read('/srv/app');
    }

    public function test_read_missing_throws_path_not_found(): void
    {
        $this->expectException(PathNotFound::class);
        $this->fs()->read('/srv/app/no-such-file-zzz');
    }
}
