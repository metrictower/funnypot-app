<?php

declare(strict_types=1);

namespace Funnypot\Shell\Fs;

/**
 * The private per-install secret that keys host identity + FS content, defeating the oracle-replay
 * attack (the generator + wordlists are public). Resolution: env FUNNYPOT_FS_SECRET, else a persisted
 * file on the data volume, else generate + persist once. Never goes dark for a missing secret; never
 * logged or echoed. Persisted like the SQLite store so it survives container recreate.
 */
final class HostSecret
{
    private const FILENAME = 'fs_secret';

    public static function resolve(string $storageDir): string
    {
        $env = getenv('FUNNYPOT_FS_SECRET');
        if (is_string($env) && $env !== '') {
            return $env;
        }

        $path = rtrim($storageDir, '/') . '/' . self::FILENAME;
        if (is_file($path)) {
            $bytes = @file_get_contents($path);
            if (is_string($bytes) && $bytes !== '') {
                return $bytes;
            }
        }

        $secret = random_bytes(32);
        if (!is_dir($storageDir)) {
            @mkdir($storageDir, 0700, true);
        }
        @file_put_contents($path, $secret, LOCK_EX);
        @chmod($path, 0600);

        return $secret;
    }
}
