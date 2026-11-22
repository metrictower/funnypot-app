<?php

declare(strict_types=1);

namespace Funnypot\App\Storage;

use Funnypot\App\Tarpit\Ssrf\SsrfState;
use PDO;
use PDOException;
use Throwable;

/**
 * The SSRF decoy's own SQLite file (ssrf-decoy.sqlite).
 *
 * One row per account holds its hooks, imports and export destination as JSON; one row per request
 * source holds its hourly unit ledger and write count. Every request runs inside one BEGIN IMMEDIATE:
 * load both rows, charge the units, decide, write, COMMIT, and only then does the caller emit a byte,
 * so a page never shows a delivery the store does not hold. A store error (busy or locked, I/O, a
 * failed COMMIT, a store that would not open) comes back as one typed failure with nothing changed. A
 * state change past a write cap is refused but its units are still charged, so the ledger keeps
 * bounding a capped source. A non-store throwable from the decision rolls back and propagates.
 *
 * Keyed hashes only: accounts are keyed by an HMAC of the token-mint row, its epoch and the account
 * serial; sources by an HMAC of the address. Bounded on every axis: at most MAX rows of each kind,
 * idle-expiring after a day, each state row capped by SsrfState::ROW_CAP, the attribution table FIFO
 * and age capped, and per-source and global hourly write caps.
 */
final class SsrfStore
{
    public const BUSY_TIMEOUT_MS = 100;
    public const FAIL_STORE = 'store';
    public const FAIL_CAP = 'cap';

    /** @var array<string,int> */
    public const DEFAULTS = [
        'owners' => 4000,
        'ledgers' => 4000,
        'idle_s' => 86400,
        'source_writes_hr' => 600,
        'global_writes_hr' => 20000,
        'turns' => 20000,
        'turns_ttl_s' => 604800,
    ];

    private ?PDO $db = null;
    private bool $failed = false;

    /** @var array<string,int> */
    private array $limits;

    /**
     * @param array<string,int> $limits overrides of DEFAULTS (tests use small values)
     * @param object|null $faults test hook with a stage(string) method called at 'begin', 'load', 'write'
     *        and 'commit'; it may throw a PDOException to simulate that failure
     */
    public function __construct(private string $path, array $limits = [], private ?object $faults = null)
    {
        $this->limits = array_merge(self::DEFAULTS, $limits);
    }

    public function ready(): bool
    {
        return $this->db() !== null;
    }

    public function path(): string
    {
        return $this->path;
    }

    /** Read one account's state without a transaction. Any fault reads as none. */
    public function load(string $owner): ?SsrfState
    {
        try {
            $db = $this->db();
            if ($db === null) {
                return null;
            }
            $st = $db->prepare('SELECT state FROM ssrf_owner WHERE o = :o');
            $st->execute([':o' => $owner]);
            $json = $st->fetchColumn();

            return is_string($json) ? SsrfState::fromJson($json) : null;
        } catch (Throwable $e) {
            return null;
        }
    }

    /**
     * Run a decision inside BEGIN IMMEDIATE on account $owner and source $source.
     *
     * @return array{ok:bool,failure:?string,value:mixed}
     */
    public function transact(string $owner, string $source, int $now, SsrfDecision $decision): array
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
            $st = $db->prepare('SELECT state FROM ssrf_owner WHERE o = :o');
            $st->execute([':o' => $owner]);
            $json = $st->fetchColumn();
            $hasOwner = is_string($json);
            $state = $hasOwner ? SsrfState::fromJson($json) : null;
            $l = $db->prepare('SELECT hour, units, writes FROM ssrf_ledger WHERE s = :s');
            $l->execute([':s' => $source]);
            $ledger = $l->fetch(PDO::FETCH_ASSOC) ?: null;
            $sameHour = $ledger !== null && (int) $ledger['hour'] === $hour;
            $units = $sameHour ? (int) $ledger['units'] : 0;
            $writes = $sameHour ? (int) $ledger['writes'] : 0;
            $g = $db->prepare('SELECT writes FROM ssrf_gauge WHERE hour = :h');
            $g->execute([':h' => $hour]);
            $gauge = (int) ($g->fetchColumn() ?: 0);
            $capReached = $writes >= $this->limits['source_writes_hr'] || $gauge >= $this->limits['global_writes_hr'];

            $db->exec('SAVEPOINT decision');
            $out = $decision->decide($state, new SsrfTx($now, $units, $capReached));
            $failure = null;
            $change = $out->state !== null && $out->stateChange;
            if ($change && $capReached) {
                $db->exec('ROLLBACK TO decision');
                $failure = self::FAIL_CAP;
                $change = false;
            } elseif ($out->state !== null) {
                if (!$out->state->fits()) {
                    $this->rollback();

                    return self::fail(self::FAIL_STORE);
                }
                $this->fault('write');
                $db->prepare('INSERT INTO ssrf_owner (o, state, seen) VALUES (:o, :s, :n) ON CONFLICT(o) DO UPDATE SET state = excluded.state, seen = excluded.seen')
                    ->execute([':o' => $owner, ':s' => $out->state->toJson(), ':n' => $now]);
                if ($change) {
                    $db->prepare('INSERT INTO ssrf_gauge (hour, writes) VALUES (:h, 1) ON CONFLICT(hour) DO UPDATE SET writes = writes + 1')->execute([':h' => $hour]);
                }
            }
            $this->fault('write');
            $db->prepare('INSERT INTO ssrf_ledger (s, hour, units, writes, seen) VALUES (:s, :h, :u, :w, :n)
                ON CONFLICT(s) DO UPDATE SET hour = excluded.hour, units = excluded.units, writes = excluded.writes, seen = excluded.seen')
                ->execute([':s' => $source, ':h' => $hour, ':u' => $units + $out->units, ':w' => $writes + ($change ? 1 : 0), ':n' => $now]);
            if (($out->state !== null && !$hasOwner && $failure === null) || $ledger === null) {
                $this->prune($db, $now, $owner, $source);
            }
            $this->fault('commit');
            $db->exec('COMMIT');

            return $failure !== null ? self::fail($failure) : ['ok' => true, 'failure' => null, 'value' => $out->value];
        } catch (PDOException $e) {
            $this->rollback();

            return self::fail(self::FAIL_STORE);
        } catch (Throwable $e) {
            $this->rollback();
            throw $e;
        }
    }

    /**
     * Best-effort attribution row; never served, never read by a request.
     *
     * @param array<string,string> $turn
     */
    public function attribute(string $s8, int $now, array $turn): void
    {
        try {
            $db = $this->db();
            if ($db === null) {
                return;
            }
            $db->prepare('INSERT INTO ssrf_turns (ts, s8, route, tclass, nkind, outcome, t8) VALUES (:ts, :s8, :r, :c, :k, :o, :t)')
                ->execute([
                    ':ts' => $now, ':s8' => substr($s8, 0, 16), ':r' => substr($turn['route'] ?? '', 0, 32), ':c' => substr($turn['tclass'] ?? '', 0, 16),
                    ':k' => substr($turn['nkind'] ?? '', 0, 16), ':o' => substr($turn['outcome'] ?? '', 0, 24), ':t' => substr($turn['t8'] ?? '', 0, 16),
                ]);
            $id = (int) $db->lastInsertId();
            if ($id % 64 === 0) {
                $db->prepare('DELETE FROM ssrf_turns WHERE id <= :id OR ts < :old')
                    ->execute([':id' => $id - $this->limits['turns'], ':old' => $now - $this->limits['turns_ttl_s']]);
            }
        } catch (Throwable $e) {
            // attribution only; the answer is already out
        }
    }

    /** The open connection, for tests and the metrics script. */
    public function db(): ?PDO
    {
        if ($this->failed) {
            return null;
        }
        if ($this->db !== null) {
            return $this->db;
        }
        for ($attempt = 0; $attempt < 5; $attempt++) {
            try {
                return $this->db = $this->openAndMigrate();
            } catch (PDOException $e) {
                if (!str_contains($e->getMessage(), 'locked') && !str_contains($e->getMessage(), 'busy')) {
                    break;
                }
            } catch (Throwable $e) {
                break;
            }
        }
        $this->failed = true;

        return null;
    }

    private function openAndMigrate(): PDO
    {
        $db = Sqlite::open($this->path);
        $db->exec('CREATE TABLE IF NOT EXISTS ssrf_owner (o TEXT PRIMARY KEY, state TEXT NOT NULL, seen INTEGER NOT NULL)');
        $db->exec('CREATE INDEX IF NOT EXISTS ssrf_owner_seen ON ssrf_owner (seen)');
        $db->exec('CREATE TABLE IF NOT EXISTS ssrf_ledger (s TEXT PRIMARY KEY, hour INTEGER NOT NULL, units INTEGER NOT NULL, writes INTEGER NOT NULL, seen INTEGER NOT NULL)');
        $db->exec('CREATE INDEX IF NOT EXISTS ssrf_ledger_seen ON ssrf_ledger (seen)');
        $db->exec('CREATE TABLE IF NOT EXISTS ssrf_turns (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, s8 TEXT NOT NULL, route TEXT NOT NULL, tclass TEXT NOT NULL, nkind TEXT NOT NULL, outcome TEXT NOT NULL, t8 TEXT NOT NULL)');
        $db->exec('CREATE TABLE IF NOT EXISTS ssrf_gauge (hour INTEGER PRIMARY KEY, writes INTEGER NOT NULL)');
        $db->exec('PRAGMA busy_timeout=' . self::BUSY_TIMEOUT_MS);

        return $db;
    }

    private function prune(PDO $db, int $now, string $owner, string $source): void
    {
        $old = $now - $this->limits['idle_s'];
        foreach ([['ssrf_owner', 'o', $owner, 'owners'], ['ssrf_ledger', 's', $source, 'ledgers']] as [$table, $key, $keep, $limit]) {
            $db->prepare("DELETE FROM {$table} WHERE {$key} IN (SELECT {$key} FROM {$table} WHERE seen < :old AND {$key} != :keep LIMIT 64)")
                ->execute([':old' => $old, ':keep' => $keep]);
            $over = (int) $db->query("SELECT COUNT(*) FROM {$table}")->fetchColumn() - $this->limits[$limit];
            if ($over > 0) {
                $db->prepare("DELETE FROM {$table} WHERE {$key} IN (SELECT {$key} FROM {$table} WHERE {$key} != :keep ORDER BY seen ASC LIMIT :n)")
                    ->execute([':keep' => $keep, ':n' => $over]);
            }
        }
        $db->prepare('DELETE FROM ssrf_gauge WHERE hour < :h')->execute([':h' => intdiv($now, 3600) - 24]);
    }

    private function fault(string $stage): void
    {
        $this->faults?->stage($stage);
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
