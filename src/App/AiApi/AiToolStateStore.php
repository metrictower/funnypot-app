<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi;

use PDO;
use Throwable;

/**
 * The sole ledger for the bounded tool-calling loop. It never stores a prompt, schema, argument, result,
 * raw IP, auth value, cookie, call id, tool name or model output — only opaque SHA-256 correlation
 * digests, so it corroborates "did this decoy actually issue the call this result claims to answer"
 * without retaining anything sensitive. Request history stays authoritative for call count and ordering
 * (chat clients resend the whole transcript); the store only atomically single-consumes a returned
 * result so a replay cannot advance the loop twice, and its per-scope keying keeps two actors from
 * reading or advancing each other's state.
 *
 * Its own file (never the shared bait/fake-state tables), created in a private 0700 directory as mode
 * 0600 and never following a symlink. Every operation is fail-open: a locked/broken/missing store makes
 * the caller degrade to a plausible stateless response, never a 500 or a retry loop.
 */
final class AiToolStateStore
{
    /** consume() outcomes. */
    public const CONSUMED = 'consumed';   // this call was ours and had not been answered yet
    public const REPLAYED = 'replayed';   // no matching unconsumed row (unknown/replayed/expired)
    public const ERROR = 'error';         // store fault — caller degrades statelessly

    private const EXPIRY_S = 900;          // 15 minutes
    private const BUSY_TIMEOUT_MS = 25;
    private const PRUNE_BATCH = 64;
    private const MAX_LIVE_PER_SCOPE = 8;
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
        return \dirname($hitDbPath) . '/ai-state/ai-tool-state.sqlite';
    }

    /**
     * Record that the decoy issued a call, keyed by its correlation digest under a per-actor+conversation
     * scope. Returns false on any cap/fault so the caller can still serve a stateless call. Never throws.
     */
    public function issue(string $scope, string $correlator, string $provider, int $turn): bool
    {
        try {
            $db = $this->db();
            if ($db === null) {
                return false;
            }
            $now = ($this->clock)();
            $db->exec('BEGIN IMMEDIATE');
            $this->pruneFallback($db, $now);

            $total = (int) $db->query('SELECT COUNT(*) FROM issued_calls')->fetchColumn();
            $scopeLive = (int) $this->countScope($db, $scope, $now);
            if ($scopeLive >= self::MAX_LIVE_PER_SCOPE || $total >= self::MAX_ROWS) {
                $db->exec('ROLLBACK');

                return false;
            }

            $st = $db->prepare(
                'INSERT INTO issued_calls (scope, correlator, provider, turn, issued_at, expires_at, consumed_at)
                 VALUES (:scope, :corr, :prov, :turn, :iat, :exp, NULL)'
            );
            $st->execute([
                ':scope' => $scope,
                ':corr' => $correlator,
                ':prov' => $provider,
                ':turn' => $turn,
                ':iat' => $now,
                ':exp' => $now + self::EXPIRY_S,
            ]);
            $db->exec('COMMIT');

            return true;
        } catch (Throwable $e) {
            $this->rollback();
            $this->failed = true;

            return false;
        }
    }

    /**
     * Atomically consume exactly one unexpired, unconsumed row matching $correlator. A concurrent or
     * replayed result therefore has exactly one winner; every other caller sees REPLAYED. Never throws.
     */
    public function consume(string $correlator): string
    {
        try {
            $db = $this->db();
            if ($db === null) {
                return self::ERROR;
            }
            $now = ($this->clock)();
            $db->exec('BEGIN IMMEDIATE');
            $sel = $db->prepare('SELECT id FROM issued_calls WHERE correlator = :corr AND consumed_at IS NULL AND expires_at >= :now ORDER BY id LIMIT 1');
            $sel->execute([':corr' => $correlator, ':now' => $now]);
            $id = $sel->fetchColumn();
            if ($id === false) {
                $db->exec('ROLLBACK');

                return self::REPLAYED;
            }
            $upd = $db->prepare('UPDATE issued_calls SET consumed_at = :now WHERE id = :id AND consumed_at IS NULL');
            $upd->execute([':now' => $now, ':id' => (int) $id]);
            $changed = $upd->rowCount();
            $db->exec('COMMIT');

            return $changed === 1 ? self::CONSUMED : self::REPLAYED;
        } catch (Throwable $e) {
            $this->rollback();
            $this->failed = true;

            return self::ERROR;
        }
    }

    private function countScope(PDO $db, string $scope, int $now): int
    {
        $st = $db->prepare('SELECT COUNT(*) FROM issued_calls WHERE scope = :s AND consumed_at IS NULL AND expires_at >= :now');
        $st->execute([':s' => $scope, ':now' => $now]);

        return (int) $st->fetchColumn();
    }

    private function pruneFallback(PDO $db, int $now): void
    {
        $ids = $db->query('SELECT id FROM issued_calls WHERE consumed_at IS NOT NULL OR expires_at < ' . $now . ' ORDER BY id LIMIT ' . self::PRUNE_BATCH)->fetchAll(PDO::FETCH_COLUMN);
        if ($ids) {
            $db->exec('DELETE FROM issued_calls WHERE id IN (' . implode(',', array_map('intval', $ids)) . ')');
        }
    }

    private function rollback(): void
    {
        try {
            if ($this->db !== null && $this->db->inTransaction()) {
                $this->db->exec('ROLLBACK');
            }
        } catch (Throwable $e) {
            // ignore
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
                'CREATE TABLE IF NOT EXISTS issued_calls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scope TEXT NOT NULL,
                    correlator TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    turn INTEGER NOT NULL,
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    consumed_at INTEGER
                )'
            );
            $db->exec('CREATE INDEX IF NOT EXISTS idx_calls_corr ON issued_calls(correlator, consumed_at, expires_at)');
            $db->exec('CREATE INDEX IF NOT EXISTS idx_calls_scope ON issued_calls(scope, consumed_at, expires_at)');

            return $this->db = $db;
        } catch (Throwable $e) {
            $this->failed = true;

            return null;
        }
    }
}
