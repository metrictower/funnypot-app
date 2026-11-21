<?php

declare(strict_types=1);

namespace Funnypot\App\Storage;

use Funnypot\App\Tarpit\Cmdi\SourceState;
use PDO;
use Throwable;

/**
 * The console's per-source history, in its own `cmdi-shell.sqlite` beside the hit store (one file per
 * concern). It sits on the request path, so it is small, bounded and fail-open:
 *
 *  - `cmdi_shell` holds one row per source, keyed by a keyed hash of the IP (no raw IP is stored).
 *    A row holds closed-set values and capped paths only, never more than 12 KB
 *    ({@see SourceState::MAX_ROW_BYTES}). Rows idle for four hours expire, at most 2000 rows are kept
 *    (least recently seen go first), and
 *    a source may write at most 600 times an hour. A gauge row caps all writes at 20,000 an hour, so
 *    a flood from rotating IPs cannot grow the file. Over a cap the turn is answered statelessly.
 *  - `cmdi_turns` is an attribution log for the operator (what each turn got and why). It is never
 *    served, keeps at most 20,000 rows, and drops rows older than seven days.
 *
 * It opens through {@see Sqlite::open()} (so the file is 0666 before WAL, shared by php-fpm and root
 * listeners) and then drops the busy timeout to 25 ms: a locked file costs a request at most that
 * long, then the turn runs without history. Any fault leaves load() empty and save() a no-op.
 */
final class CmdiShellStateStore implements CmdiShellStore
{
    public const BUSY_TIMEOUT_MS = 25;
    public const TTL_S = 4 * 3600;
    public const MAX_ROWS = 2000;
    public const PER_SOURCE_HR = 600;
    public const GLOBAL_HR = 20000;
    public const TURNS_CAP = 20000;
    public const TURNS_RETAIN_S = 7 * 86400;

    /** The gauge row's key; real keys are 32 hex characters, so this can never collide. */
    private const GAUGE = '#global';

    private ?PDO $db = null;
    private bool $failed = false;
    /** @var callable():int */
    private $clock;

    public function __construct(
        private string $dbPath,
        private string $storeKey,
        ?callable $clock = null,
        private int $maxRows = self::MAX_ROWS,
        private int $globalHr = self::GLOBAL_HR,
        private int $turnsCap = self::TURNS_CAP,
    ) {
        $this->clock = $clock ?? static fn (): int => time();
    }

    public static function defaultPath(string $hitDbPath): string
    {
        return dirname($hitDbPath) . '/cmdi-shell.sqlite';
    }

    /** The stored key for a source: 32 hex characters of a keyed hash, never the IP itself. */
    public function key(string $ip): string
    {
        return substr(hash_hmac('sha256', $ip, $this->storeKey), 0, 32);
    }

    public function load(string $ip): SourceState
    {
        try {
            $db = $this->db();
            if ($db === null) {
                return SourceState::empty();
            }
            $st = $db->prepare('SELECT state, seen FROM cmdi_shell WHERE k = ?');
            if ($st === false || !$st->execute([$this->key($ip)])) {
                return SourceState::empty();
            }
            $row = $st->fetch(PDO::FETCH_ASSOC);
            if (!is_array($row) || (int) $row['seen'] < $this->now() - self::TTL_S) {
                return SourceState::empty();
            }

            return SourceState::fromJson((string) $row['state']);
        } catch (Throwable $e) {
            return SourceState::empty();
        }
    }

    public function save(string $ip, array $delta, array $turn): bool
    {
        try {
            $db = $this->db();
            if ($db === null || $db->exec('BEGIN IMMEDIATE') === false) {
                return false;
            }
            try {
                // BEGIN IMMEDIATE holds the write lock from the read on, so the delta lands on the row
                // exactly as the last committed turn left it.
                $ok = $this->write($db, $this->key($ip), $delta, $turn);
                $db->exec($ok ? 'COMMIT' : 'ROLLBACK');

                return $ok;
            } catch (Throwable $e) {
                $db->exec('ROLLBACK');

                return false;
            }
        } catch (Throwable $e) {
            return false;
        }
    }

    /** @param array<string,scalar|null> $turn */
    /** @param array<string,mixed> $delta @param array<string,scalar|null> $turn */
    private function write(PDO $db, string $k, array $delta, array $turn): bool
    {
        $now = $this->now();
        $hour = intdiv($now, 3600);

        $row = $this->row($db, $k);
        $turns = ($row !== null && (int) $row['hour'] === $hour) ? (int) $row['turns'] : 0;
        if ($turns >= self::PER_SOURCE_HR) {
            return false;
        }
        $gauge = $this->row($db, self::GAUGE);
        $global = ($gauge !== null && (int) $gauge['hour'] === $hour) ? (int) $gauge['turns'] : 0;
        if ($global >= $this->globalHr) {
            return false;
        }

        $current = SourceState::empty();
        $st = $db->prepare('SELECT state, seen FROM cmdi_shell WHERE k = ?');
        if ($st !== false && $st->execute([$k]) && is_array($cur = $st->fetch(PDO::FETCH_ASSOC)) && (int) $cur['seen'] >= $now - self::TTL_S) {
            $current = SourceState::fromJson((string) $cur['state']);
        }
        $json = $current->apply($delta)->toJson();
        if (strlen($json) > SourceState::MAX_ROW_BYTES) {
            return false;
        }
        $upsert = $db->prepare(
            'INSERT INTO cmdi_shell (k, state, turns, hour, seen) VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(k) DO UPDATE SET state = excluded.state, turns = excluded.turns, hour = excluded.hour, seen = excluded.seen'
        );
        if ($upsert === false
            || !$upsert->execute([$k, $json, $turns + 1, $hour, $now])
            || !$upsert->execute([self::GAUGE, '{}', $global + 1, $hour, $now])) {
            return false;
        }

        $db->exec('DELETE FROM cmdi_shell WHERE k != ' . $db->quote(self::GAUGE) . ' AND seen < ' . ($now - self::TTL_S));
        $count = (int) $db->query('SELECT COUNT(*) FROM cmdi_shell WHERE k != ' . $db->quote(self::GAUGE))->fetchColumn();
        if ($count > $this->maxRows) {
            $db->exec('DELETE FROM cmdi_shell WHERE k IN (SELECT k FROM cmdi_shell WHERE k != ' . $db->quote(self::GAUGE)
                . ' ORDER BY seen ASC, rowid ASC LIMIT ' . ($count - $this->maxRows) . ')');
        }

        $ins = $db->prepare(
            'INSERT INTO cmdi_turns (ts, k, identity, value_source, simple, kind, sub, family, msg_id, owned_by_rule, console_rule, delay_ms)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
        );
        if ($ins === false || !$ins->execute([
            $now, $k,
            (string) ($turn['identity'] ?? ''), (string) ($turn['value_source'] ?? ''), (int) ($turn['simple'] ?? 0),
            (string) ($turn['kind'] ?? ''), (string) ($turn['sub'] ?? ''), (string) ($turn['family'] ?? ''),
            (string) ($turn['msg_id'] ?? ''), (string) ($turn['owned_by_rule'] ?? ''), (string) ($turn['console_rule'] ?? ''),
            (int) ($turn['delay_ms'] ?? 0),
        ])) {
            return false;
        }
        $db->exec('DELETE FROM cmdi_turns WHERE ts < ' . ($now - self::TURNS_RETAIN_S));
        $db->exec('DELETE FROM cmdi_turns WHERE id <= (SELECT MAX(id) FROM cmdi_turns) - ' . $this->turnsCap);

        return true;
    }

    /** @return array{turns:int|string,hour:int|string}|null */
    private function row(PDO $db, string $k): ?array
    {
        $st = $db->prepare('SELECT turns, hour FROM cmdi_shell WHERE k = ?');
        if ($st === false || !$st->execute([$k])) {
            return null;
        }
        $row = $st->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? $row : null;
    }

    private function now(): int
    {
        return (int) ($this->clock)();
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
            $db = Sqlite::open($this->dbPath);
            $db->exec('PRAGMA busy_timeout=' . self::BUSY_TIMEOUT_MS);
            $db->exec('CREATE TABLE IF NOT EXISTS cmdi_shell (
                k TEXT PRIMARY KEY, state TEXT NOT NULL, turns INTEGER NOT NULL DEFAULT 0,
                hour INTEGER NOT NULL DEFAULT 0, seen INTEGER NOT NULL DEFAULT 0)');
            $db->exec('CREATE INDEX IF NOT EXISTS cmdi_shell_seen ON cmdi_shell (seen)');
            $db->exec('CREATE TABLE IF NOT EXISTS cmdi_turns (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, k TEXT NOT NULL, identity TEXT NOT NULL,
                value_source TEXT NOT NULL, simple INTEGER NOT NULL, kind TEXT NOT NULL, sub TEXT NOT NULL,
                family TEXT NOT NULL, msg_id TEXT NOT NULL, owned_by_rule TEXT NOT NULL, console_rule TEXT NOT NULL,
                delay_ms INTEGER NOT NULL)');
            $db->exec('CREATE INDEX IF NOT EXISTS cmdi_turns_ts ON cmdi_turns (ts)');
            $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_SILENT);

            return $this->db = $db;
        } catch (Throwable $e) {
            $this->failed = true;

            return null;
        }
    }
}
