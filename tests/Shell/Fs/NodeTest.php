<?php

declare(strict_types=1);

namespace Funnypot\Tests\Shell\Fs;

use Funnypot\Shell\Fs\Node;
use Funnypot\Shell\Fs\PathNotFound;
use PHPUnit\Framework\TestCase;

final class NodeTest extends TestCase
{
    public function test_node_flags(): void
    {
        $d = new Node('etc', 'dir', 0, 0, 4096, 0o755, 1_700_000_000, null);
        self::assertTrue($d->isDir());
        self::assertFalse($d->isFile());
        $f = new Node('x', 'file', 0, 0, 12, 0o644, 1_700_000_000, null);
        self::assertTrue($f->isFile());
        self::assertFalse($f->isDir());
    }

    public function test_pathnotfound_message(): void
    {
        $e = PathNotFound::for('/no/such');
        self::assertInstanceOf(\RuntimeException::class, $e);
        self::assertStringContainsString('/no/such', $e->getMessage());
    }
}
