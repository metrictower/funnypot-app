<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

use Funnypot\App\Identity\IdentityFileOps;
use PDO;
use RuntimeException;

/**
 * The service subsystem's own SQLite opener. It deliberately does NOT use Storage\Sqlite::open(),
 * which forces the file to 0666 so php-fpm and root can share it — the service stores are private:
 * the desired store is 0660 root:www-data (PHP writes it, root reads it) and the runtime store is
 * 0600 root:root (PHP never opens it). It applies the shared WAL/busy_timeout pragmas and, when
 * running as root, re-applies group/mode to the db and any existing -wal/-shm sidecar so a sidecar
 * recreated under root cannot lock www-data out of the -shm (the trap Storage\Sqlite documents). A
 * setgid parent directory closes the window between the root open and this chgrp.
 */
final class ServiceSqlite
{
    /**
     * @param string      $path  the db path (its dir must already exist with the right owner/mode)
     * @param int         $mode  0660 (group-shared) or 0600 (root-only)
     * @param string|null $group the group to own the file+sidecars when root (e.g. www-data); null = leave
     */
    public static function open(string $path, int $mode, ?string $group = null, ?IdentityFileOps $ops = null): PDO
    {
        $ops ??= new IdentityFileOps();
        if (!extension_loaded('pdo_sqlite')) {
            throw new RuntimeException('service store needs ext-pdo_sqlite');
        }
        $old = umask(0007);
        try {
            $db = new PDO('sqlite:' . $path, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
            $db->exec('PRAGMA busy_timeout=3000');
            $db->exec('PRAGMA journal_mode=WAL');
            $db->exec('PRAGMA synchronous=NORMAL');
        } finally {
            umask($old);
        }
        self::applyOwnership($path, $mode, $group, $ops);

        return $db;
    }

    private static function applyOwnership(string $path, int $mode, ?string $group, IdentityFileOps $ops): void
    {
        $isRoot = $ops->euid() === 0;
        $gid = null;
        if ($isRoot && $group !== null) {
            $g = $ops->groupByName($group);
            if ($g !== null && isset($g['gid'])) {
                $gid = (int) $g['gid'];
            }
        }
        foreach ([$path, $path . '-wal', $path . '-shm'] as $f) {
            if ($ops->lstat($f) === false) {
                continue;
            }
            if ($gid !== null) {
                $ops->chgrp($f, $gid);
            }
            $ops->chmod($f, $mode);
        }
    }
}
