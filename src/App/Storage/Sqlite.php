<?php

declare(strict_types=1);

namespace Funnypot\App\Storage;

use PDO;

/**
 * The one place the app opens a SQLite file. It applies the pragmas every funnypot SQLite store
 * needs (WAL so many readers never block the single writer, a busy_timeout so a scan burst queues
 * instead of erroring, and incremental auto-vacuum so size-based retention can hand freed pages
 * back to disk) and forces the file mode so the php-fpm workers and the root protocol listeners can
 * share it. It is deliberately **schema-agnostic**: it creates no tables, so every concern
 * (hits/rollups, and FP-0242's config store) reuses the same open/pragma seam over its own file
 * while keeping one SQLite file per concern (docs/DATA-LAYER-DECISION.md).
 */
final class Sqlite
{
    /**
     * Open (creating if missing) the SQLite file at $path with the shared pragmas and return the
     * connection. The caller creates whatever tables/indexes it owns.
     */
    public static function open(string $path): PDO
    {
        $dir = dirname($path);
        if (!is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }
        $db = new PDO('sqlite:' . $path, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        // SQLite creates the file 0644 no matter the umask. Force 0666 so the php-fpm workers
        // (www-data) and the root protocol listeners can share this one file. Do it BEFORE enabling
        // WAL: sqlite creates the -wal/-shm sidecars copying the db file's mode, and WAL needs the
        // -shm writable even for readers. A root listener opens the db every boot, so a stale
        // root-owned db from a prior run is re-chmodded here too.
        @chmod($path, 0666);
        $db->exec('PRAGMA busy_timeout=3000');
        $db->exec('PRAGMA journal_mode=WAL');
        $db->exec('PRAGMA synchronous=NORMAL');
        // Incremental auto-vacuum so GB-based retention can hand freed pages back to disk without a
        // full VACUUM. Must be set before any table exists to take on a fresh db; a legacy db
        // (auto_vacuum=NONE) is converted once by the caller after its tables are ensured.
        $db->exec('PRAGMA auto_vacuum=INCREMENTAL');

        return $db;
    }
}
