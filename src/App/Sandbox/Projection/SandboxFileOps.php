<?php

declare(strict_types=1);

namespace Funnypot\App\Sandbox\Projection;

use Funnypot\App\Identity\IdentityFileOps;

/** @internal Filesystem seam for deterministic fault and ownership tests. */
class SandboxFileOps extends IdentityFileOps
{
    /** @param resource $h */
    public function fdatasync($h): bool
    {
        return @fdatasync($h);
    }

    public function chown(string $path, int $uid): bool
    {
        return @chown($path, $uid);
    }

    public function rmdir(string $path): bool
    {
        return @rmdir($path);
    }

    /** @param resource $h */
    public function rewind($h): bool
    {
        return @rewind($h);
    }
}
