<?php

declare(strict_types=1);

namespace Funnypot\App\Storage;

use Closure;
use Funnypot\App\Tarpit\Mint\MintState;
use PDO;
use PDOException;
use Throwable;

/**
 * The token-mint surface's own SQLite file (token-mint.sqlite).
 *
 * One row per source holds its whole account state as JSON. Single-use OAuth codes and rotating
 * refresh tokens live in their own tables so a replay is caught by a row count, not by comparing
 * JSON. Every state-changing request runs inside one BEGIN IMMEDIATE: load, decide, write, COMMIT,
 * and only then does the caller emit a byte, so the page never shows a credential the store does not
 * hold. Any store error inside a transaction (busy or locked, an I/O error, a failed COMMIT, a store
 * that would not open or migrate, a write cap) comes back as one typed failure with nothing changed;
 * the caller answers it with its coherent failure page. A non-store throwable from the decision rolls
 * back and propagates.
 *
 * Keyed hashes only: rows are keyed by an HMAC of the source, and codes, refresh tokens and client
 * secrets are stored as HMACs. No raw IP and no raw secret is ever written. Bounded on every axis:
 * at most MAX_ROWS rows idle-expiring after a day, each row capped by MintState::ROW_CAP, FIFO caps
 * on the code, refresh and attribution tables, and per-source and global hourly write caps.
 */
final class TokenMintStore
{
    public const BUSY_TIMEOUT_MS = 100;
    public const FAIL_STORE = 'store';
    public const FAIL_CAP = 'cap';

    /** @var array<string,int> */
    public const DEFAULTS = [
        'rows' => 2000,
        'idle_s' => 86400,
        'source_writes_hr' => 600,
        'global_writes_hr' => 20000,
        'codes' => 20000,
        'refresh' => 20000,
        'turns' => 20000,
        'turns_ttl_s' => 604800,
        'codes_per_account' => 4,
        'refresh_per_account' => 8,
    ];

    private ?PDO $db = null;
    private bool $failed = false;

    /** @var array<string,int> */
    private array $limits;

    /**
     * @param array<string,int> $limits overrides of DEFAULTS (tests use small values)
     * @param Closure(string):void|null $faults test hook called at each transaction stage
     *        ('begin', 'load', 'write', 'commit'); it may throw a PDOException to simulate that failure
     */
    public function __construct(private string $path, array $limits = [], private ?Closure $faults = null)
    {
        $this->limits = array_merge(self::DEFAULTS, $limits);
    }

    /** Open and migrate now; false when the store is unusable, so the surface stays unwired. */
    public function ready(): bool
    {
        return $this->db() !== null;
    }

    public function limit(string $name): int
    {
        return $this->limits[$name];
    }

    /** Read one row without a transaction. Any fault reads as no row. */
    public function load(string $k): ?MintState
    {
        try {
            $db = $this->db();
            if ($db === null) {
                return null;
            }
            $st = $db->prepare('SELECT state FROM mint_state WHERE k = :k');
            $st->execute([':k' => $k]);
            $json = $st->fetchColumn();

            return is_string($json) ? MintState::fromJson($json) : null;
        } catch (Throwable $e) {
            return null;
        }
    }

    /**
     * The rows whose 8-byte prefix matches, for addressing a bearer token. Read-only, fail-open.
     *
     * @return array<string,MintState> k => state
     */
    public function rowsByK8(string $k8hex): array
    {
        try {
            $db = $this->db();
            if ($db === null) {
                return [];
            }
            $st = $db->prepare('SELECT k, state FROM mint_state WHERE k8 = :k8 LIMIT 4');
            $st->execute([':k8' => $k8hex]);
            $out = [];
            foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) {
                $s = MintState::fromJson((string) $r['state']);
                if ($s !== null) {
                    $out[(string) $r['k']] = $s;
                }
            }

            return $out;
        } catch (Throwable $e) {
            return [];
        }
    }

    /** @return array<string,mixed>|null a code row (used or not), read without a transaction */
    public function codeRow(string $h): ?array
    {
        return $this->sideRow('mint_codes', $h);
    }

    /** @return array<string,mixed>|null */
    public function refreshRow(string $h): ?array
    {
        return $this->sideRow('mint_refresh', $h);
    }

    /**
     * Run $fn inside BEGIN IMMEDIATE on row $k. $fn gets the row's state (null when there is none)
     * and a {@see TokenMintTx} for the side tables, and returns a {@see TokenMintOutcome}.
     *
     * @param callable(?MintState, TokenMintTx):TokenMintOutcome $fn
     * @return array{ok:bool,failure:?string,value:mixed}
     */
    public function transact(string $k, string $k8hex, int $now, callable $fn): array
    {
        $db = $this->db();
        if ($db === null) {
            return self::fail(self::FAIL_STORE);
        }
        try {
            $this->fault('begin');
            $db->exec('BEGIN IMMEDIATE');
        } catch (PDOException $e) {
            return self::fail(self::FAIL_STORE);
        }
        try {
            $this->fault('load');
            $hour = intdiv($now, 3600);
            $st = $db->prepare('SELECT state, hour, writes, units FROM mint_state WHERE k = :k');
            $st->execute([':k' => $k]);
            $row = $st->fetch(PDO::FETCH_ASSOC) ?: null;
            $state = $row !== null ? MintState::fromJson((string) $row['state']) : null;
            $sameHour = $row !== null && (int) $row['hour'] === $hour;
            $writes = $sameHour ? (int) $row['writes'] : 0;
            $units = $sameHour ? (int) $row['units'] : 0;
            $g = $db->prepare('SELECT writes FROM mint_gauge WHERE hour = :h');
            $g->execute([':h' => $hour]);
            $gauge = (int) ($g->fetchColumn() ?: 0);
            $capReached = $writes >= $this->limits['source_writes_hr'] || $gauge >= $this->limits['global_writes_hr'];

            $tx = new TokenMintTx($db, $k, $now, $units, $capReached, $this->limits);
            $db->exec('SAVEPOINT decision');
            $out = $fn($state, $tx);
            if (!$out instanceof TokenMintOutcome) {
                throw new \LogicException('transaction body must return an outcome');
            }

            if ($out->state !== null) {
                if ($out->stateChange && $capReached) {
                    // The refused write still costs its units, so the hourly ledger keeps bounding the source:
                    // undo the decision's own writes, keep the charge.
                    $db->exec('ROLLBACK TO decision');
                    if ($row !== null && $out->units > 0) {
                        $this->fault('write');
                        $db->prepare('UPDATE mint_state SET hour = :h, writes = :w, units = :u WHERE k = :k')
                            ->execute([':h' => $hour, ':w' => $writes, ':u' => $units + $out->units, ':k' => $k]);
                    }
                    $this->fault('commit');
                    $db->exec('COMMIT');

                    return self::fail(self::FAIL_CAP);
                }
                if (!$out->state->fit($now)) {
                    $this->rollback();

                    return self::fail(self::FAIL_STORE);
                }
                $this->fault('write');
                $up = $db->prepare(
                    'INSERT INTO mint_state (k, k8, state, hour, writes, units, seen) VALUES (:k, :k8, :s, :h, :w, :u, :seen)
                     ON CONFLICT(k) DO UPDATE SET state = excluded.state, hour = excluded.hour, writes = excluded.writes,
                     units = excluded.units, seen = excluded.seen'
                );
                $up->execute([
                    ':k' => $k, ':k8' => $k8hex, ':s' => $out->state->toJson(), ':h' => $hour,
                    ':w' => $writes + ($out->stateChange ? 1 : 0), ':u' => $units + $out->units, ':seen' => $now,
                ]);
                if ($out->stateChange || $tx->sideWrites > 0) {
                    $db->prepare('INSERT INTO mint_gauge (hour, writes) VALUES (:h, 1) ON CONFLICT(hour) DO UPDATE SET writes = writes + 1')
                        ->execute([':h' => $hour]);
                }
                if ($row === null) {
                    $this->pruneRows($db, $now, $k);
                }
            } elseif ($row !== null && $out->units > 0) {
                $this->fault('write');
                $db->prepare('UPDATE mint_state SET hour = :h, writes = :w, units = :u WHERE k = :k')
                    ->execute([':h' => $hour, ':w' => $writes, ':u' => $units + $out->units, ':k' => $k]);
            }
            $this->fault('commit');
            $db->exec('COMMIT');

            return ['ok' => true, 'failure' => null, 'value' => $out->value];
        } catch (PDOException $e) {
            $this->rollback();

            return self::fail(self::FAIL_STORE);
        } catch (Throwable $e) {
            $this->rollback();
            throw $e;
        }
    }

    /**
     * Best-effort attribution row (route, outcome, friction kind, scopes, token kind). Never served,
     * never read by a request; FIFO-capped and pruned after TURNS_TTL_S.
     *
     * @param array<string,string> $turn
     */
    public function attribute(string $k8hex, int $now, array $turn): void
    {
        try {
            $db = $this->db();
            if ($db === null) {
                return;
            }
            $db->prepare('INSERT INTO mint_turns (ts, k8, route, outcome, friction, scopes, kind) VALUES (:ts, :k8, :r, :o, :f, :s, :kind)')
                ->execute([
                    ':ts' => $now, ':k8' => $k8hex,
                    ':r' => substr($turn['route'] ?? '', 0, 32), ':o' => substr($turn['outcome'] ?? '', 0, 32),
                    ':f' => substr($turn['friction'] ?? '', 0, 32), ':s' => substr($turn['scopes'] ?? '', 0, 160),
                    ':kind' => substr($turn['kind'] ?? '', 0, 8),
                ]);
            $id = (int) $db->lastInsertId();
            if ($id % 64 === 0) {
                $db->prepare('DELETE FROM mint_turns WHERE id <= :id OR ts < :old')
                    ->execute([':id' => $id - $this->limits['turns'], ':old' => $now - $this->limits['turns_ttl_s']]);
            }
        } catch (Throwable $e) {
            // attribution only; the answer is already out
        }
    }

    /** The open connection, for tests and the report script. */
    public function db(): ?PDO
    {
        if ($this->failed) {
            return null;
        }
        if ($this->db !== null) {
            return $this->db;
        }
        // Two workers opening a brand-new file at once can see "database is locked" on the WAL switch,
        // which the busy timeout does not cover. That clears in microseconds, so retry briefly, and
        // never latch it as a permanent failure.
        $transient = false;
        for ($attempt = 0; $attempt < 5; $attempt++) {
            try {
                return $this->db = $this->openAndMigrate();
            } catch (PDOException $e) {
                $transient = str_contains($e->getMessage(), 'locked') || str_contains($e->getMessage(), 'busy');
                if (!$transient) {
                    break;
                }
                usleep(1000 << $attempt);
            } catch (Throwable $e) {
                $transient = false;
                break;
            }
        }
        $this->failed = !$transient;

        return null;
    }

    private function openAndMigrate(): PDO
    {
        $db = Sqlite::open($this->path);
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        // The schema is created under Sqlite::open()'s longer busy timeout, so two workers
        // creating a fresh file at once both succeed; requests then fail fast.
        $db->exec('CREATE TABLE IF NOT EXISTS mint_state (k TEXT PRIMARY KEY, k8 TEXT NOT NULL, state TEXT NOT NULL, hour INTEGER NOT NULL, writes INTEGER NOT NULL, units INTEGER NOT NULL, seen INTEGER NOT NULL)');
        $db->exec('CREATE INDEX IF NOT EXISTS mint_state_k8 ON mint_state (k8)');
        $db->exec('CREATE INDEX IF NOT EXISTS mint_state_seen ON mint_state (seen)');
        $db->exec('CREATE TABLE IF NOT EXISTS mint_codes (h TEXT PRIMARY KEY, k TEXT NOT NULL, acct INTEGER NOT NULL, app INTEGER NOT NULL, scopes TEXT NOT NULL, state_ref TEXT NOT NULL, expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0)');
        $db->exec('CREATE INDEX IF NOT EXISTS mint_codes_owner ON mint_codes (k, acct)');
        $db->exec('CREATE TABLE IF NOT EXISTS mint_refresh (h TEXT PRIMARY KEY, k TEXT NOT NULL, acct INTEGER NOT NULL, app INTEGER NOT NULL, scopes TEXT NOT NULL, expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0)');
        $db->exec('CREATE INDEX IF NOT EXISTS mint_refresh_owner ON mint_refresh (k, acct)');
        $db->exec('CREATE TABLE IF NOT EXISTS mint_turns (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, k8 TEXT NOT NULL, route TEXT NOT NULL, outcome TEXT NOT NULL, friction TEXT NOT NULL, scopes TEXT NOT NULL, kind TEXT NOT NULL)');
        $db->exec('CREATE TABLE IF NOT EXISTS mint_gauge (hour INTEGER PRIMARY KEY, writes INTEGER NOT NULL)');
        $db->exec('PRAGMA busy_timeout=' . self::BUSY_TIMEOUT_MS);

        return $db;
    }

    /** @return array<string,mixed>|null */
    private function sideRow(string $table, string $h): ?array
    {
        try {
            $db = $this->db();
            if ($db === null) {
                return null;
            }
            $st = $db->prepare('SELECT * FROM ' . ($table === 'mint_codes' ? 'mint_codes' : 'mint_refresh') . ' WHERE h = :h');
            $st->execute([':h' => $h]);
            $r = $st->fetch(PDO::FETCH_ASSOC);

            return is_array($r) ? $r : null;
        } catch (Throwable $e) {
            return null;
        }
    }

    private function pruneRows(PDO $db, int $now, string $keep): void
    {
        $db->prepare('DELETE FROM mint_state WHERE k IN (SELECT k FROM mint_state WHERE seen < :old AND k != :keep LIMIT 64)')
            ->execute([':old' => $now - $this->limits['idle_s'], ':keep' => $keep]);
        $count = (int) $db->query('SELECT COUNT(*) FROM mint_state')->fetchColumn();
        $over = $count - $this->limits['rows'];
        if ($over > 0) {
            $db->prepare('DELETE FROM mint_state WHERE k IN (SELECT k FROM mint_state WHERE k != :keep ORDER BY seen ASC LIMIT :n)')
                ->execute([':keep' => $keep, ':n' => $over]);
        }
        $db->prepare('DELETE FROM mint_gauge WHERE hour < :h')->execute([':h' => intdiv($now, 3600) - 24]);
    }

    private function fault(string $stage): void
    {
        if ($this->faults !== null) {
            ($this->faults)($stage);
        }
    }

    private function rollback(): void
    {
        try {
            $this->db?->exec('ROLLBACK');
        } catch (Throwable $e) {
            // no transaction was open, so nothing to undo
        }
    }

    /** @return array{ok:bool,failure:?string,value:mixed} */
    private static function fail(string $why): array
    {
        return ['ok' => false, 'failure' => $why, 'value' => null];
    }
}
