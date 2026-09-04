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

    /**
     * True when {@see resolve()} yields a secret that survives the process — from the env or the
     * persisted file. False means resolve() degraded to a per-process value (unwritable volume),
     * so anything keyed on it would differ per worker; callers that need a stable install-local
     * key must treat that as "no key" rather than key on it.
     */
    public static function isPersisted(string $storageDir): bool
    {
        $env = getenv('FUNNYPOT_FS_SECRET');
        if (is_string($env) && $env !== '') {
            return true;
        }
        $path = rtrim($storageDir, '/') . '/' . self::FILENAME;
        clearstatcache(true, $path);

        return is_file($path) && (int) @filesize($path) > 0;
    }

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
        // Exclusive-create so exactly ONE process wins the first-boot race: the telnet and ssh listeners
        // (separate processes) must converge on the same secret, or they'd present different boxes. A
        // last-writer-wins put + re-read does NOT guarantee that; O_EXCL does.
        $fp = @fopen($path, 'xb');
        if ($fp !== false) {
            fwrite($fp, $secret);
            fclose($fp);
            @chmod($path, 0600);

            return $secret;
        }
        // Lost the race (or the file already existed) — adopt whatever is on disk.
        $onDisk = @file_get_contents($path);
        if (is_string($onDisk) && $onDisk !== '') {
            return $onDisk;
        }
        // Couldn't create AND couldn't read → unwritable dir. Never silent: identity won't survive a
        // restart and may differ between listeners (a tell). Degrade to a per-process secret.
        error_log('funnypot: FS host secret could not be persisted to ' . $path
            . ' — set FUNNYPOT_FS_SECRET or fix the data-volume permissions');

        return $secret;
    }
}
