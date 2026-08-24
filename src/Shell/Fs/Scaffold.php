<?php

declare(strict_types=1);

namespace Funnypot\Shell\Fs;

/**
 * The fixed FHS skeleton every host always has. Real Linux roots are not random — a fixed shallow
 * scaffold guarantees the standard dirs exist (so walk-validate and recon anchors never miss), with
 * procedural fill below. Pinned files (Task 7) and per-user homes (Phase 3) layer on top.
 */
final class Scaffold
{
    /** @var array<string,string[]> canonical dir path => always-present child dir names */
    private const DIRS = [
        '/' => ['bin', 'boot', 'dev', 'etc', 'home', 'lib', 'lib64', 'media', 'mnt', 'opt', 'proc',
            'root', 'run', 'sbin', 'srv', 'tmp', 'usr', 'var'],
        '/usr' => ['bin', 'lib', 'local', 'sbin', 'share', 'include'],
        '/usr/local' => ['bin', 'lib', 'share', 'sbin'],
        '/var' => ['log', 'lib', 'backups', 'cache', 'spool', 'www', 'tmp'],
        '/var/www' => ['html'],
        '/srv' => ['app'],
        '/etc' => [],   // contents largely pinned (Task 7) + procedural fill
        '/home' => [],  // per-user homes added in Phase 3; procedural fill for now
        '/opt' => [],
        '/root' => [],
    ];

    /** @return string[]|null declared child names, or null if this is not a scaffold dir */
    public static function childrenOf(string $canonPath): ?array
    {
        return self::DIRS[$canonPath] ?? null;
    }

    public static function isScaffoldDir(string $canonPath): bool
    {
        return array_key_exists($canonPath, self::DIRS);
    }
}
