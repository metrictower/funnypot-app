<?php

declare(strict_types=1);

namespace Funnypot\App\Llm;

use PDO;
use Throwable;

/**
 * Global generations-per-hour ceiling for the LLM fake path — the backstop the per-IP velocity gate
 * cannot be. Gate A keys on one source IP, so a rotating-IP flood (every source under the per-IP
 * window) never trips it, and the in-flight cap bounds parallelism, not rate: a handful of slots at
 * a couple of seconds each still allows thousands of sidecar calls an hour, each inserting a fresh
 * cache key that churns the LRU under the byte-identical fakes real revisits depend on. This ledger
 * counts every successful sidecar call in the current hour bucket, across all IPs, and stops NEW
 * generation once the cap is spent. Cached fakes keep serving (the responder's cache read precedes
 * the gate), so exhaustion costs only fresh generations — never a cached page, never the plain 404.
 *
 * Same SQLite file and PDO idiom as {@see CircuitBreaker}, so the count is shared across php-fpm
 * workers. exhausted() fails CLOSED like {@see \Funnypot\App\Storage\TarpitBudget::overBudget()}: if
 * the budget cannot be verified, spend nothing (cache and the static 404 still serve, so a ledger
 * fault is neither a self-DoS nor a tell). charge() is best-effort — a lost charge only under-counts.
 */
final class LlmGenBudget
{
    private ?PDO $db = null;

    /** @var callable():int */
    private $clock;

    /**
     * @param int                 $perHour fresh generations allowed per hour bucket, across all IPs
     * @param callable():int|null $clock   injectable unix-time source for tests (defaults to time())
     */
    public function __construct(private string $dbPath, private int $perHour = 60, ?callable $clock = null)
    {
        $this->clock = $clock ?? static fn (): int => time();
    }

    /** True once this hour's generations have reached the cap — or the ledger cannot be read. */
    public function exhausted(): bool
    {
        try {
            return $this->spent() >= max(1, $this->perHour);
        } catch (Throwable $e) {
            return true;   // fail-closed: an unverifiable budget spends nothing
        }
    }

    /** Count one successful sidecar generation against the current hour. Best-effort. */
    public function charge(): void
    {
        try {
            $this->db()->prepare(
                'INSERT INTO llm_gen_ledger (hour_bucket, gens) VALUES (:h, 1)
                 ON CONFLICT(hour_bucket) DO UPDATE SET gens = gens + 1'
            )->execute([':h' => $this->hourBucket()]);
        } catch (Throwable $e) {
            // best-effort
        }
    }

    /** Generations charged in the current hour bucket. Throws on a storage fault (exhausted() maps it). */
    public function spent(): int
    {
        $st = $this->db()->prepare('SELECT gens FROM llm_gen_ledger WHERE hour_bucket = :h');
        $st->execute([':h' => $this->hourBucket()]);

        return (int) ($st->fetchColumn() ?: 0);
    }

    /** Drop ledger buckets older than $keepHours (retention). Returns rows removed. */
    public function pruneLedger(int $keepHours = 3): int
    {
        try {
            $st = $this->db()->prepare('DELETE FROM llm_gen_ledger WHERE hour_bucket < :c');
            $st->execute([':c' => $this->hourBucket() - max(1, $keepHours)]);

            return $st->rowCount();
        } catch (Throwable $e) {
            return 0;
        }
    }

    private function hourBucket(): int
    {
        return intdiv(($this->clock)(), 3600);
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
        $db->exec('CREATE TABLE IF NOT EXISTS llm_gen_ledger (hour_bucket INTEGER PRIMARY KEY, gens INTEGER NOT NULL DEFAULT 0)');

        return $this->db = $db;
    }
}
