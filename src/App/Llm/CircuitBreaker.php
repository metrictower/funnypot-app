<?php

declare(strict_types=1);

namespace Funnypot\App\Llm;

use PDO;
use Throwable;

/**
 * A tiny SQLite-backed circuit breaker so a dead/slow sidecar does not add timeout-latency to every
 * unmatched request. N consecutive failures open it for a cooldown; while open, the client skips the
 * socket call entirely. SQLite-backed (not in-process) so the state is shared across php-fpm workers.
 * Fails open (allow) if its own store is unreadable — the breaker must never be the thing that breaks.
 *
 * Three states, one row: closed (allow) → open (shed until the cooldown lapses) → half-open (exactly
 * ONE caller probes the sidecar while its peers keep shedding) → closed on a probe success, or straight
 * back to open on a probe failure. Without the half-open step every worker is released at once when the
 * cooldown lapses, all pay the full timeout against a still-dead sidecar, and the breaker re-trips — an
 * open/stampede/open latency sawtooth that is itself a timing fingerprint of a model behind the 404.
 * With it, at most one request per cooldown pays the timeout. The failure count is an atomic upsert:
 * a read-then-write from two workers loses increments and delays the trip.
 */
final class CircuitBreaker
{
    private ?PDO $db = null;

    /** @var callable():int */
    private $clock;

    /** @param callable():int|null $clock injectable unix-time source for tests (defaults to time()) */
    public function __construct(
        private string $dbPath,
        private int $threshold = 5,
        private int $cooldownSecs = 30,
        ?callable $clock = null,
    ) {
        $this->clock = $clock ?? static fn (): int => time();
    }

    /**
     * False while the breaker is shedding. Once an open breaker's cooldown lapses, one caller claims the
     * half-open probe slot with a conditional UPDATE — rowCount() tells the claimer from its peers, who
     * stay shed until the probe reports. The claim stamps a fresh deadline: a probe that never reports
     * (worker died mid-call) would otherwise wedge the breaker shut, so a lapsed half-open is claimable
     * again by the same UPDATE — self-healing, no reaper.
     */
    public function allow(): bool
    {
        try {
            $st = $this->db()->prepare("SELECT state, until FROM breaker WHERE k = 'llm'");
            $st->execute();
            $row = $st->fetch(PDO::FETCH_ASSOC);
            if ($row === false) {
                return true;
            }
            $now = ($this->clock)();
            $until = strtotime((string) $row['until']) ?: 0;
            if (($row['state'] ?? 'closed') === 'closed') {
                return $until <= $now;   // a row from before the state column marks open by `until` alone
            }
            if ($until > $now) {
                return false;   // open, or a live half-open probe: shed
            }
            $claim = $this->db()->prepare(
                "UPDATE breaker SET state = 'half-open', until = :u
                 WHERE k = 'llm' AND state IN ('open', 'half-open') AND until <= :now"
            );
            $claim->execute([':u' => gmdate('c', $now + $this->cooldownSecs), ':now' => gmdate('c', $now)]);

            return $claim->rowCount() === 1;
        } catch (Throwable $e) {
            return true;   // fail open
        }
    }

    public function recordSuccess(): void
    {
        $this->set('closed', 0, '');
    }

    public function recordFailure(): void
    {
        try {
            $db = $this->db();
            // A failed half-open probe re-opens for a full cooldown at once — it never counts toward
            // the threshold, or the peers it held back would be released against a sidecar just seen dead.
            $reopen = $db->prepare("UPDATE breaker SET state = 'open', failures = 0, until = :u WHERE k = 'llm' AND state = 'half-open'");
            $reopen->execute([':u' => gmdate('c', ($this->clock)() + $this->cooldownSecs)]);
            if ($reopen->rowCount() === 1) {
                return;
            }
            // The increment is one upsert under SQLite's writer lock, so concurrent failures can never
            // both read N and both write N+1. The trip below may fire from two workers; both write the
            // same open state, so that race is idempotent.
            $db->prepare(
                "INSERT INTO breaker (k, failures, until, state) VALUES ('llm', 1, '', 'closed')
                 ON CONFLICT(k) DO UPDATE SET failures = failures + 1"
            )->execute();
            $st = $db->prepare("SELECT failures FROM breaker WHERE k = 'llm'");
            $st->execute();
            if ((int) $st->fetchColumn() >= $this->threshold) {
                $this->set('open', 0, gmdate('c', ($this->clock)() + $this->cooldownSecs));
            }
        } catch (Throwable $e) {
            // best-effort
        }
    }

    private function set(string $state, int $failures, string $until): void
    {
        try {
            $this->db()->prepare("INSERT OR REPLACE INTO breaker (k, failures, until, state) VALUES ('llm', :f, :u, :s)")
                ->execute([':f' => $failures, ':u' => $until, ':s' => $state]);
        } catch (Throwable $e) {
            // best-effort
        }
    }

    private function db(): PDO
    {
        if ($this->db !== null) {
            return $this->db;
        }
        $dir = dirname($this->dbPath);
        if (!is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }
        $db = new PDO('sqlite:' . $this->dbPath, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        @chmod($this->dbPath, 0666);
        $db->exec('PRAGMA busy_timeout=3000');
        $db->exec('PRAGMA journal_mode=WAL');
        $db->exec(
            'CREATE TABLE IF NOT EXISTS breaker (k TEXT PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0,'
            . " until TEXT NOT NULL DEFAULT '', state TEXT NOT NULL DEFAULT 'closed')"
        );
        // A table from before the state column: add it in place. Idempotent — every later boot hits
        // the duplicate-column error and ignores it; a legacy open row reads as open by `until` alone.
        try {
            $db->exec("ALTER TABLE breaker ADD COLUMN state TEXT NOT NULL DEFAULT 'closed'");
        } catch (Throwable $e) {
            // column already present
        }

        return $this->db = $db;
    }
}
