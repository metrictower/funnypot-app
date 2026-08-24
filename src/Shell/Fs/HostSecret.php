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
        $ok = @file_put_contents($path, $secret, LOCK_EX);
        @chmod($path, 0600);

        // A concurrent first-boot writer may have won the race; adopt whatever is now on disk so all
        // processes converge on ONE secret (a per-process-fresh secret would reshuffle host identity).
        $onDisk = @file_get_contents($path);
        if (is_string($onDisk) && $onDisk !== '') {
            return $onDisk;
        }
        if ($ok === false) {
            // Never silent: an unpersistable secret means identity won't survive a restart — a tell.
            error_log('funnypot: FS host secret could not be persisted to ' . $path
                . ' — set FUNNYPOT_FS_SECRET or fix the data-volume permissions');
        }

        return $secret;
    }
}
