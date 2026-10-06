<?php

declare(strict_types=1);

namespace Funnypot\App\Storage;

use PDO;
use Throwable;

/**
 * FP-0467 Phase 1: the bounded capture ledger for the semi-blind file-write trap. When a cmdi payload
 * writes a sentinel to a webroot file (`echo TAG > /var/www/html/out.txt`), the capture hook records the
 * (canonical path -> content) here under a per-apparent-source scope; a subsequent verify request for that
 * path serves the stored content back (the scanner's own sentinel), confirming its blind write-then-fetch
 * technique. Modelled on AiToolStateStore: its own SQLite file in a private 0700 dir as mode 0600, never
 * following a symlink; every op is FAIL-OPEN (a locked/broken/missing store returns false/null so the
 * caller degrades to today's stateless behaviour, never a 500 or a retry loop).
 *
 * INERT by construction: memory of the attacker's OWN bytes only, nothing executed, never written to the
 * real disk outside this bounded ledger, bounded per-scope + globally, TTL-expired. It stores no raw IP —
 * the caller passes an opaque source scope. The decision of WHETHER to serve a captured byte (the
 * deception) is the verify hook's job (phase 3), gated to the dedicated-box / isolated-origin posture;
 * this store only records and looks up.
 */
final class WriteCaptureStore
{
    private const EXPIRY_S = 1800;            // 30 minutes — a scan's write+verify window
    private const BUSY_TIMEOUT_MS = 25;
    private const PRUNE_BATCH = 64;
    private const MAX_FILES_PER_SCOPE = 64;   // one source cannot flood the ledger
    private const MAX_CONTENT_BYTES = 65536;  // 64 KB cap per captured file (truncated beyond)
    private const MAX_ROWS = 5000;            // global backstop

    private ?PDO $db = null;
    private bool $failed = false;

    /** @var callable():int */
    private $clock;

    public function __construct(private string $dbPath, ?callable $clock = null)
    {
        $this->clock = $clock ?? 'time';
    }

    public static function defaultPath(string $hitDbPath): string
    {
        return \dirname($hitDbPath) . '/write-capture/write-capture.sqlite';
    }

    /**
     * Record (or overwrite) a captured write for a source. Content beyond the cap is truncated. Returns
     * false on any cap/fault so the caller still serves its normal response. Never throws.
     */
    public function capture(string $scope, string $path, string $content, string $contentType): bool
    {
        if ($scope === '' || $path === '') {
            return false;
        }
        try {
            $db = $this->db();
            if ($db === null) {
                return false;
            }
            $now = ($this->clock)();
            $content = \substr($content, 0, self::MAX_CONTENT_BYTES);
            $contentType = \substr($contentType, 0, 128);
            $expires = $now + self::EXPIRY_S;

            $db->exec('BEGIN IMMEDIATE');
            $this->pruneFallback($db, $now);

            // Overwrite an existing (scope,path) — an attacker re-dropping the same file.
            $upd = $db->prepare('UPDATE captures SET content = :c, content_type = :ct, captured_at = :now, expires_at = :exp WHERE scope = :s AND path = :p');
            $upd->execute([':c' => $content, ':ct' => $contentType, ':now' => $now, ':exp' => $expires, ':s' => $scope, ':p' => $path]);
            if ($upd->rowCount() === 0) {
                $scopeLive = (int) $this->countScope($db, $scope, $now);
                $total = (int) $db->query('SELECT COUNT(*) FROM captures')->fetchColumn();
                if ($scopeLive >= self::MAX_FILES_PER_SCOPE || $total >= self::MAX_ROWS) {
                    $db->exec('ROLLBACK');

                    return false;
                }
                $ins = $db->prepare('INSERT INTO captures (scope, path, content, content_type, captured_at, expires_at) VALUES (:s, :p, :c, :ct, :now, :exp)');
                $ins->execute([':s' => $scope, ':p' => $path, ':c' => $content, ':ct' => $contentType, ':now' => $now, ':exp' => $expires]);
            }
            $db->exec('COMMIT');

            return true;
        } catch (Throwable $e) {
            $this->rollback();

            return false;
        }
    }

    /**
     * Look up a captured write for a source + path (unexpired). Returns {content, content_type,
     * captured_at} or null (not found / expired / fault — the caller then serves its normal 404/decoy).
     *
     * @return array{content:string,content_type:string,captured_at:int}|null
     */
    public function verify(string $scope, string $path): ?array
    {
        if ($scope === '' || $path === '') {
            return null;
        }
        try {
            $db = $this->db();
            if ($db === null) {
                return null;
            }
            $now = ($this->clock)();
            $sel = $db->prepare('SELECT content, content_type, captured_at FROM captures WHERE scope = :s AND path = :p AND expires_at >= :now LIMIT 1');
            $sel->execute([':s' => $scope, ':p' => $path, ':now' => $now]);
            $row = $sel->fetch(PDO::FETCH_ASSOC);
            if ($row === false) {
                return null;
            }

            return [
                'content' => (string) $row['content'],
                'content_type' => (string) $row['content_type'],
                'captured_at' => (int) $row['captured_at'],
            ];
        } catch (Throwable $e) {
            return null;
        }
    }

    /**
     * List a source's unexpired captured files (path + size + type + time), for a WebDAV PROPFIND so an
     * attacker sees its own dropped files listed. Fail-open to [] (caller shows only the canned root).
     *
     * @return list<array{path:string,size:int,content_type:string,captured_at:int}>
     */
    public function listForScope(string $scope): array
    {
        if ($scope === '') {
            return [];
        }
        try {
            $db = $this->db();
            if ($db === null) {
                return [];
            }
            $now = ($this->clock)();
            $sel = $db->prepare('SELECT path, LENGTH(content) AS size, content_type, captured_at FROM captures WHERE scope = :s AND expires_at >= :now ORDER BY captured_at DESC LIMIT ' . self::MAX_FILES_PER_SCOPE);
            $sel->execute([':s' => $scope, ':now' => $now]);
            $out = [];
            foreach ($sel->fetchAll(PDO::FETCH_ASSOC) as $row) {
                $out[] = [
                    'path' => (string) $row['path'],
                    'size' => (int) $row['size'],
                    'content_type' => (string) $row['content_type'],
                    'captured_at' => (int) $row['captured_at'],
                ];
            }

            return $out;
        } catch (Throwable $e) {
            return [];
        }
    }

    /** Remove a source's captured file (for a WebDAV MOVE/DELETE). Fail-open to false; never throws. */
    public function remove(string $scope, string $path): bool
    {
        if ($scope === '' || $path === '') {
            return false;
        }
        try {
            $db = $this->db();
            if ($db === null) {
                return false;
            }
            $del = $db->prepare('DELETE FROM captures WHERE scope = :s AND path = :p');
            $del->execute([':s' => $scope, ':p' => $path]);

            return $del->rowCount() > 0;
        } catch (Throwable $e) {
            return false;
        }
    }

    private function countScope(PDO $db, string $scope, int $now): int
    {
        $st = $db->prepare('SELECT COUNT(*) FROM captures WHERE scope = :s AND expires_at >= :now');
        $st->execute([':s' => $scope, ':now' => $now]);

        return (int) $st->fetchColumn();
    }

    private function pruneFallback(PDO $db, int $now): void
    {
        $ids = $db->query('SELECT id FROM captures WHERE expires_at < ' . $now . ' ORDER BY id LIMIT ' . self::PRUNE_BATCH)->fetchAll(PDO::FETCH_COLUMN);
        if ($ids !== []) {
            $db->exec('DELETE FROM captures WHERE id IN (' . implode(',', array_map('intval', $ids)) . ')');
        }
    }

    private function rollback(): void
    {
        try {
            if ($this->db !== null) {
                $this->db->exec('ROLLBACK');
            }
        } catch (Throwable $e) {
            // already rolled back / no transaction — ignore
        }
    }

    private function db(): ?PDO
    {
        if ($this->db !== null) {
            return $this->db;
        }
        if ($this->failed) {
            return null;
        }
        try {
            $dir = \dirname($this->dbPath);
            if (is_link($dir) || is_link($this->dbPath)) {
                $this->failed = true;

                return null;
            }
            if (!is_dir($dir)) {
                @mkdir($dir, 0700, true);
            }
            @chmod($dir, 0700);
            $db = new PDO('sqlite:' . $this->dbPath, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
            @chmod($this->dbPath, 0600);
            $db->exec('PRAGMA busy_timeout=' . self::BUSY_TIMEOUT_MS);
            $db->exec('PRAGMA journal_mode=WAL');
            $db->exec('PRAGMA synchronous=NORMAL');
            $db->exec(
                'CREATE TABLE IF NOT EXISTS captures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scope TEXT NOT NULL,
                    path TEXT NOT NULL,
                    content BLOB NOT NULL,
                    content_type TEXT NOT NULL,
                    captured_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                )'
            );
            $db->exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_cap_scope_path ON captures(scope, path)');
            $db->exec('CREATE INDEX IF NOT EXISTS idx_cap_expires ON captures(expires_at)');

            return $this->db = $db;
        } catch (Throwable $e) {
            $this->failed = true;

            return null;
        }
    }
}
