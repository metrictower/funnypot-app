<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Sandbox;

/** Bounded fixture cleanup: never follows links and only receives each test's unpredictable root. */
final class SandboxTestFiles
{
    public static function remove(string $path): void
    {
        $st = @lstat($path);
        if (!is_array($st)) { return; }
        if ((((int) $st['mode']) & 0170000) !== 0040000) { @unlink($path); return; }
        @chmod($path, 0700);
        $names = @scandir($path);
        if (is_array($names)) {
            foreach ($names as $name) {
                if ($name !== '.' && $name !== '..') { self::remove($path . '/' . $name); }
            }
        }
        @rmdir($path);
    }
}
