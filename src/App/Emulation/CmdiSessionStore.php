<?php

declare(strict_types=1);

namespace Funnypot\App\Emulation;

use PDO;
use Throwable;

/**
 * FP-0531 piece 2: the short-lived per-source binding of a confirmed Commix tag pair. When a source
 * confirms command injection with `<LEFT>$((expr))<RIGHT>`, bind() records (opaque source scope ->
 * left,right) so a later execute follow-up carrying the SAME pair can be matched to that source and
 * answered with bracketed output. Keeping it source-bound (not matching bare tag-wrapped commands
 * statelessly) is what makes the execution-phase oracle precise and low-FP.
 *
 * Modelled on AiToolStateStore / WriteCaptureStore: its own SQLite file in a private 0700 dir as mode
 * 0600, never following a symlink; every op FAIL-OPEN (broken/locked store -> false/null, caller degrades
 * to a plain 404, never a 500). Bounded + SHORT TTL (a confirm→execute handshake is seconds-to-minutes),
 * capacity-capped, pruned. Stores an opaque source scope + the attacker's OWN tags — no raw IP, no payload.
 */
final class CmdiSessionStore
{
    private const TTL_S = 600;              // 10 minutes — a confirm→execute handshake window
    private const BUSY_TIMEOUT_MS = 25;
    private const PRUNE_BATCH = 64;
    private const MAX_ROWS = 5000;

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
        return \dirname($hitDbPath) . '/cmdi-session/cmdi-session.sqlite';
    }

    /** Bind a confirmed tag pair to a source (overwrites an earlier binding for the same source). */
    public function bind(string $scope, string $left, string $right): bool
    {
        if ($scope === '' || $left === '' || $right === '') {
            return false;
        }
        try {
            $db = $this->db();
            if ($db === null) {
                return false;
            }
            $now = ($this->clock)();
            $exp = $now + self::TTL_S;
            $db->exec('BEGIN IMMEDIATE');
            $this->pruneFallback($db, $now);
            $upd = $db->prepare('UPDATE cmdi_sessions SET lefttag = :l, righttag = :r, expires_at = :exp WHERE scope = :s');
            $upd->execute([':l' => $left, ':r' => $right, ':exp' => $exp, ':s' => $scope]);
            if ($upd->rowCount() === 0) {
                if ((int) $db->query('SELECT COUNT(*) FROM cmdi_sessions')->fetchColumn() >= self::MAX_ROWS) {
                    $db->exec('ROLLBACK');

                    return false;
                }
                $ins = $db->prepare('INSERT INTO cmdi_sessions (scope, lefttag, righttag, expires_at) VALUES (:s, :l, :r, :exp)');
                $ins->execute([':s' => $scope, ':l' => $left, ':r' => $right, ':exp' => $exp]);
            }
            $db->exec('COMMIT');

            return true;
        } catch (Throwable $e) {
            $this->rollback();

            return false;
        }
    }

    /**
     * Is (left,right) the pair this source confirmed with, still live? Only then does the execution-phase
     * oracle answer the follow-up (precision gate).
     */
    public function isBound(string $scope, string $left, string $right): bool
    {
        if ($scope === '' || $left === '' || $right === '') {
            return false;
        }
        try {
            $db = $this->db();
            if ($db === null) {
                return false;
            }
            $now = ($this->clock)();
            $sel = $db->prepare('SELECT 1 FROM cmdi_sessions WHERE scope = :s AND lefttag = :l AND righttag = :r AND expires_at >= :now LIMIT 1');
            $sel->execute([':s' => $scope, ':l' => $left, ':r' => $right, ':now' => $now]);

            return $sel->fetchColumn() !== false;
        } catch (Throwable $e) {
            return false;
        }
    }

    private function pruneFallback(PDO $db, int $now): void
    {
        $ids = $db->query('SELECT id FROM cmdi_sessions WHERE expires_at < ' . $now . ' ORDER BY id LIMIT ' . self::PRUNE_BATCH)->fetchAll(PDO::FETCH_COLUMN);
        if ($ids !== []) {
            $db->exec('DELETE FROM cmdi_sessions WHERE id IN (' . implode(',', array_map('intval', $ids)) . ')');
        }
    }

    private function rollback(): void
    {
        try {
            if ($this->db !== null) {
                $this->db->exec('ROLLBACK');
            }
        } catch (Throwable $e) {
            // no active transaction — ignore
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
                'CREATE TABLE IF NOT EXISTS cmdi_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scope TEXT NOT NULL,
                    lefttag TEXT NOT NULL,
                    righttag TEXT NOT NULL,
                    expires_at INTEGER NOT NULL
                )'
            );
            $db->exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_cmdi_scope ON cmdi_sessions(scope)');

            return $this->db = $db;
        } catch (Throwable $e) {
            $this->failed = true;

            return null;
        }
    }
}
