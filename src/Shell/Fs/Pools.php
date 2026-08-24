<?php

declare(strict_types=1);

namespace Funnypot\Shell\Fs;

/**
 * Role-biased factual name pools for procedural generation. Each role is merged with the shared
 * 'generic' base (role entries first, so they bias the draw), then deduped. Large pools are a
 * fingerprint defense: the pool is public, so an exact-string match must not be proof of fakeness.
 */
final class Pools
{
    /** @var array<string,array<string,string[]>>|null */
    private static ?array $data = null;

    /** @return array<string,array<string,string[]>> */
    private static function load(): array
    {
        if (self::$data === null) {
            /** @var array<string,array<string,string[]>> $d */
            $d = require dirname(__DIR__, 3) . '/resources/fs-pools.php';
            self::$data = $d;
        }

        return self::$data;
    }

    /** @return string[] */
    private static function merged(string $role, string $key): array
    {
        $d = self::load();
        $roleArr = $d[$role][$key] ?? [];
        $generic = $d['generic'][$key] ?? [];

        return array_values(array_unique(array_merge($roleArr, $generic)));
    }

    /** @return string[] */
    public static function dirNames(string $role): array
    {
        return self::merged($role, 'dirs');
    }

    /** @return string[] */
    public static function fileNames(string $role): array
    {
        return self::merged($role, 'files');
    }

    /** @return string[] */
    public static function extensions(string $role): array
    {
        return self::merged($role, 'exts');
    }
}
