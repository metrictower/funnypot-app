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

    /** @param string[] $dirs @return array<string,\Funnypot\Shell\Fs\Node> canonical file path => node */
    private function findFiles(FakeFilesystem $fs, array $dirs): array
    {
        $files = [];
        foreach ($dirs as $d) {
            try {
                $nodes = $fs->list($d);
            } catch (\Throwable $e) {
                continue;
            }
            foreach ($nodes as $n) {
                if ($n->isFile()) {
                    $files[($d === '/' ? '' : $d) . '/' . $n->name] = $n;
                }
            }
        }

        return $files;
    }

    public function test_size_matches_content_length_and_is_capped(): void
    {
        $fs = $this->fs();
        $files = $this->findFiles($fs, ['/etc', '/usr/lib', '/var/log', '/srv/app', '/opt', '/root', '/usr/share']);
        self::assertNotEmpty($files);
        foreach ($files as $path => $node) {
            self::assertLessThanOrEqual(65536, $node->size);
            self::assertSame($node->size, strlen($fs->read($path)), "size mismatch for {$path}");
        }
    }

    public function test_read_is_deterministic(): void
    {
        // /etc/passwd is pinned, so guaranteed present regardless of seed.
        self::assertSame($this->fs()->read('/etc/passwd'), $this->fs()->read('/etc/passwd'));
    }

    public function test_content_has_no_periodic_padding_and_low_repetition(): void
    {
        $fs = $this->fs();
        $files = $this->findFiles($fs, ['/usr/lib', '/var/log', '/srv/app', '/opt', '/usr/share', '/home', '/var/cache', '/root']);
        $path = null;
        foreach ($files as $p => $n) {
            if ($n->size >= 200) {
                $path = $p; // a procedural file (none of these dirs are the pinned /etc)
                break;
            }
        }
        if ($path === null) {
            self::markTestSkipped('no procedural file >= 200 bytes for this seed');
        }
        $bytes = $fs->read($path);
        // B3 regression: the old base64(fnv1a64-block) put '=' every 12th char and near-identical blocks.
        self::assertStringNotContainsString('=', $bytes, 'no base64 padding inside generated content');
        // 12-char windows must not be near-identical (avalanche): most windows are distinct.
        $windows = [];
        for ($i = 0; $i + 12 <= strlen($bytes); $i += 12) {
            $windows[] = substr($bytes, $i, 12);
        }
        self::assertGreaterThan(count($windows) * 0.8, count(array_unique($windows)), 'content too repetitive');
    }

    public function test_symlink_read_does_not_return_procedural_junk(): void
    {
        // /etc/localtime is a pinned symlink; reading follows the (unresolvable) target -> PathNotFound,
        // never a base64 blob (M4).
        $this->expectException(PathNotFound::class);
        $this->fs()->read('/etc/localtime');
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
