<?php

declare(strict_types=1);

namespace Funnypot\Tests\Shell\Fs;

use Funnypot\Shell\Fs\Pools;
use PHPUnit\Framework\TestCase;

final class PoolsTest extends TestCase
{
    public function test_pools_are_large_and_unique(): void
    {
        foreach (['developer', 'finance', 'hr', 'sales', 'ops', 'generic'] as $role) {
            $dirs = Pools::dirNames($role);
            $files = Pools::fileNames($role);
            self::assertGreaterThanOrEqual(150, count($dirs), "$role dirs");
            self::assertGreaterThanOrEqual(150, count($files), "$role files");
            self::assertSame(array_values(array_unique($dirs)), $dirs, "$role dirs unique");
            self::assertSame(array_values(array_unique($files)), $files, "$role files unique");
        }
    }
}
