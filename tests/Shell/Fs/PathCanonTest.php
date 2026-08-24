<?php

declare(strict_types=1);

namespace Funnypot\Tests\Shell\Fs;

use Funnypot\Shell\Fs\PathCanon;
use PHPUnit\Framework\TestCase;

final class PathCanonTest extends TestCase
{
    public function test_canonical_forms(): void
    {
        self::assertSame('/', PathCanon::canonical('/'));
        self::assertSame('/', PathCanon::canonical('///'));
        self::assertSame('/home/bob', PathCanon::canonical('/home/bob/'));
        self::assertSame('/home', PathCanon::canonical('/home/bob/..'));
        self::assertSame('/etc', PathCanon::canonical('/home/../etc/./'));
        self::assertSame('/', PathCanon::canonical('/..')); // can't escape root
    }

    public function test_segments_and_parent(): void
    {
        self::assertSame(['home', 'bob'], PathCanon::segments('/home/bob'));
        self::assertSame([], PathCanon::segments('/'));
        self::assertSame('/home', PathCanon::parent('/home/bob'));
        self::assertSame('/', PathCanon::parent('/home'));
        self::assertSame('bob', PathCanon::basename('/home/bob'));
    }
}
