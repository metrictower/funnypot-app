<?php

declare(strict_types=1);

namespace Funnypot\App\Storage;

use PDO;
use Throwable;

/**
 * The tarpit caps, enforced cross-worker (FP-0245a). php-fpm gives 16 workers total for every port
 * (demo/fpm-pool.conf:8), so an uncapped tarpit is a self-DoS: N slow requests pin N of those 16.
 * This is the single backstop that keeps the tarpit from starving the honeypot's real job, and — on
 * the gate-exempt tarpit routes, where the per-IP velocity gate is deliberately removed
 * (spec invariant 6) — the ONLY per-IP guard. It must hold against any client, crawler or LLM,
 * well-behaved or not, and it fails CLOSED: any storage error or cap breach sheds to a bounded 404,
 * never a slow path.
 *
 * It generalises {@see LlmFakeCache}::acquire/release/reapInflight — a BEGIN IMMEDIATE slot table so
 * the count and the insert see one write-locked snapshot (no check-then-act race) — over its own
 * tarpit.sqlite, opened through the shared {@see Sqlite} helper, with two tables:
 *   - tarpit_slot(id, ip, started_at) — one row per in-flight tarpit request; the global-concurrency
 *     and per-IP-concurrency caps count rows here.
 *   - tarpit_ledger(ip, hour_bucket, bytes, wall_ms, pages) — the rolling per-IP hourly budget:
 *     bytes/IP/hr, wall-ms/IP/hr, pages/IP/hr, and a global bytes/hr aggregate.
 *
 * Two hardening choices over the LlmFakeCache precedent, both justified by the small (default 4)
 * slot pool (see the FP-0245 plan review's SHOULD-FIX 4 & 5):
 *   - the slot-reap TTL is SHORT (default 15 s, aligned to nginx fastcgi_read_timeout 15s), kept
 *     entirely separate from the 120 s/hr wall BUDGET — a 120 s slot TTL would let 4 crashed holders
 *     wedge the whole pool for two minutes;
 *   - acquire() self-reaps stale slots INLINE before the COUNT, so a crashed holder self-clears
 *     within one TTL regardless of the retention cron cadence. release() runs in a finally on the
 *     happy path, but a PHP fatal/OOM/SIGTERM never runs finally — so the inline reaper, not
 *     release(), is the real safety net for such a small pool.
 *
 * Public API note (FP-0228): acquire() returns the slot id alongside the status, and guard() is the
 * one-call "may I proceed?" seam every tarpit route MUST call first; FP-0228 extends this surface
 * (latency accounting per IP) and relies on the slot id + the ledger's wall_ms column shape.
 */
final class TarpitBudget
{
    public const WON = 'won';                 // caller holds a slot and may serve one tarpit response
    public const FULL = 'full';               // global concurrency cap reached (or fail-closed) — shed
    public const PER_IP_FULL = 'per_ip_full'; // this IP already holds its allowance — shed

    /**
     * Hard ceiling on the optional server latency (FP-0245d), enforced HERE regardless of what the
     * config passed — a second wall behind AppConfig's own clamp so an operator typo (or a future
     * caller) can never pin a worker anywhere near nginx's 15 s fastcgi_read_timeout. 2000 ms ≪ 15 s,
     * and ≪ the 15 s slot-reap TTL, so a latency-sleeping worker never outlives its own slot.
     */
    public const LATENCY_HARD_CAP_MS = 2000;

    /**
     * Ceiling on the latency jitter band. {@see applyLatency()} reserves this much headroom BELOW its
     * effective ms and adds a random amount inside it, so latency-armed responses vary instead of
     * carrying one constant added delay (a uniform-timing tell). Shared with {@see \Funnypot\App\Http\SleepDecoy},
     * which applies the same band below its per-request cap.
     */
    public const MAX_JITTER_MS = 200;

    private ?PDO $db = null;

    /** @var callable():int */
    private $clock;

    /** @var callable(int):void the latency sleeper (ms → sleep); injectable so tests don't really sleep. */
    private $sleeper;

    /** @var callable(int):int jitter source (band-ceiling ms → jitter ms in [0, ceiling]); injectable for tests. */
    private $jitter;

    /**
     * @param bool $enabled       master switch (FUNNYPOT_TARPIT); OFF => guard() is inert (always null)
     * @param int  $maxConcurrent global concurrent tarpit slots (default 4 = ¼ of the 16 workers)
     * @param int  $maxPerIp      concurrent slots one IP may hold (default 1)
     * @param int  $bytesPerIpHr  bytes one IP may pull per hour (bytes, not MiB)
     * @param int  $wallPerIpHrMs server wall-ms one IP may consume per hour (ms)
     * @param int  $globalBytesHr aggregate bytes across all IPs per hour (bytes)
     * @param int  $pagesPerIpHr  tarpit pages/responses one IP may fetch per hour
     * @param int  $slotTtlSecs   crashed-holder slot TTL (SHORT, ~nginx read-timeout) — NOT the wall budget
     * @param callable():int|null $clock injectable unix-time source for tests (defaults to time())
     * @param int  $latencyMs     optional server latency (FP-0245d) applied by {@see applyLatency()} ONLY
     *                            while a slot is held; 0 = off (default), hard-clamped ≤ LATENCY_HARD_CAP_MS
     * @param callable(int):void|null $sleeper injectable sleeper (ms) for tests; defaults to real usleep
     * @param callable(int):int|null $jitter band-ceiling-ms → jitter-ms in [0, ceiling] for
     *                            {@see applyLatency()}; defaults to random_int. Injectable so tests are deterministic
     *
     * NOTE for the 0245b/c/d wiring (flagged by the FP-0245a review): the SHORT slotTtlSecs means a
     * LEGITIMATE holder whose response streams longer than the TTL will have its slot reaped out from
     * under it, softening the concurrency ceiling. That is the deliberate trade — a short TTL is the
     * only safe reclaim for a crashed holder (release() never runs on a fatal/OOM/SIGTERM). So the
     * wiring MUST keep a single tarpit response under slotTtlSecs: the latency sleep is clamped by
     * LATENCY_HARD_CAP_MS and every streamed body is cut at the {@see \Funnypot\App\Tarpit\SeededStream::DEADLINE_MS}
     * fabrication deadline (10 s), which together fit inside the 15 s TTL. Keep that ordering (sleep +
     * deadline < TTL) if any of the three values ever moves.
     */
    public function __construct(
        private string $dbPath,
        private bool $enabled = false,
        private int $maxConcurrent = 4,
        private int $maxPerIp = 1,
        private int $bytesPerIpHr = 64 * 1024 * 1024,
        private int $wallPerIpHrMs = 120 * 1000,
        private int $globalBytesHr = 1024 * 1024 * 1024,
        private int $pagesPerIpHr = 2000,
        private int $slotTtlSecs = 15,
        ?callable $clock = null,
        private int $latencyMs = 0,
        ?callable $sleeper = null,
        ?callable $jitter = null
    ) {
        $this->clock = $clock ?? static fn (): int => time();
        $this->sleeper = $sleeper ?? static function (int $ms): void {
            usleep($ms * 1000);
        };
        $this->jitter = $jitter ?? static fn (int $ceil): int => $ceil > 0 ? random_int(0, $ceil) : 0;
    }

    /**
     * The optional server latency (FP-0245d), applied as a SINGLE bounded sleep on the calling worker.
     *
     * THE SELF-DoS INVARIANT: this holds a php-fpm worker for its whole duration, so it is only ever
     * safe because the caller reaches it ONLY after a non-null {@see guard()} — i.e. while holding one
     * of the small (default 4) TarpitBudget slots. A request that could not win a slot (or is over its
     * hourly budget, or hit the master switch) gets guard() === null and is shed to a bounded 404
     * WITHOUT ever calling this, so the number of workers ever sleeping at once can never exceed
     * MAX_CONCURRENT. Never call this outside a held slot — that would reintroduce the 16-worker DoS.
     *
     * It is a single sleep BEFORE the first byte (never a per-byte drip), hard-clamped ≤
     * LATENCY_HARD_CAP_MS regardless of config (defence behind AppConfig's clamp), and fail-safe: a
     * sleeper fault adds NO latency and never propagates (a tarpit must never fail slow, never 500).
     * The returned ms actually slept is INFORMATIONAL (telemetry/tests): the callers do NOT use it to
     * charge the ledger — they measure one hrtime wall window that SPANS this sleep and charge that, so
     * the slept time is already inside the per-IP/global wall charge. That is how an IP's repeated
     * latency accrues until it trips overBudget() and is then served immediately.
     *
     * The sleep is JITTERED the way {@see \Funnypot\App\Http\SleepDecoy} jitters its honoured delay: a
     * band of up to MAX_JITTER_MS (or a tenth of the effective ms, whichever is smaller) is reserved
     * BELOW the effective ms and a random amount inside it is added back, so the slept time lands in
     * [ms - band, ms] and varies per response instead of being one constant — a fixed added delay is a
     * timing tell. The band sits below the value, never above it, so the clamp still holds: no
     * response ever sleeps longer than the (capped) configured ms.
     */
    public function applyLatency(): int
    {
        if (!$this->enabled) {
            return 0; // master switch off — inert (defence in depth; a caller only reaches here on WON)
        }
        $ms = max(0, min(self::LATENCY_HARD_CAP_MS, $this->latencyMs));
        if ($ms <= 0) {
            return 0; // default-off / disabled
        }
        try {
            $band = min(self::MAX_JITTER_MS, intdiv($ms, 10));
            $jitter = max(0, min($band, (int) ($this->jitter)($band)));
            $slept = $ms - $band + $jitter;
            ($this->sleeper)($slept);

            return $slept;
        } catch (Throwable $e) {
            return 0; // fail-safe: no latency, never a slow/500 failure mode
        }
    }

    /**
     * FP-0228 sibling of {@see applyLatency()}: apply a PER-REQUEST latency (the honoured SLEEP the
     * attacker asked for, already capped by the caller) as ONE bounded sleep, reusing applyLatency()'s
     * exact mechanism — the SAME injected sleeper, the SAME LATENCY_HARD_CAP_MS wall (a second clamp
     * behind AppConfig's), the SAME fail-safe. It differs only in taking the ms per call instead of the
     * construction-fixed $latencyMs, because a time-based decoy's delay tracks each probe's requested
     * seconds. The SELF-DoS invariant is identical and non-negotiable: call this ONLY while holding a
     * TarpitBudget slot (i.e. after a non-null {@see guard()}), so the number of workers ever sleeping
     * at once can never exceed MAX_CONCURRENT. Returns the ms actually slept (0 on disabled / ≤0 / fault)
     * so the caller can charge that wall time to the ledger.
     */
    public function applyLatencyMs(int $requestedMs): int
    {
        if (!$this->enabled) {
            return 0; // master switch off — inert (defence in depth; a caller only reaches here on WON)
        }
        $ms = max(0, min(self::LATENCY_HARD_CAP_MS, $requestedMs));
        if ($ms <= 0) {
            return 0;
        }
        try {
            ($this->sleeper)($ms);

            return $ms;
        } catch (Throwable $e) {
            return 0; // fail-safe: no latency, never a slow/500 failure mode
        }
    }

    /**
     * The one seam every tarpit route calls FIRST (spec invariant 6, plan-review SHOULD-FIX 3). It is
     * the ONLY per-IP guard on those gate-exempt routes, so nothing may dispatch tarpit work without
     * it. Returns a held slot id when the caller may proceed, or null to shed to a bounded 404. Fails
     * closed in every branch: master switch off, over budget, no free slot, or any storage error =>
     * null. The caller releases the slot id in a finally and charges the ledger on the way out.
     *
     * Ledger overshoot bound: overBudget() and acquire() are two separate transactions, and charge()
     * lands only after the response is served, so N concurrent requests from one IP can all read
     * "under budget" before any of them is billed. What bounds the overshoot is acquire()'s per-IP
     * concurrency cap — at most $maxPerIp of those readers win a slot, so a just-crossed hourly ledger
     * can be exceeded by at most $maxPerIp in-flight responses per IP (and $maxConcurrent globally).
     * The default maxPerIp = 1 makes that "one extra response". Raising maxPerIp widens the overshoot
     * proportionally; that is a deliberate trade, not a race to fix by folding the read into the
     * acquire transaction (the ledger is best-effort by design — the hard controls are the slots).
     */
    public function guard(string $ip): ?int
    {
        if (!$this->enabled) {
            return null; // master switch off — the whole tarpit is inert
        }
        try {
            if ($this->overBudget($ip)) {
                return null; // hourly budget spent — shed
            }
            $r = $this->acquire($ip);

            return $r['status'] === self::WON ? $r['slot'] : null;
        } catch (Throwable $e) {
            return null; // fail-closed: never a slow failure mode
        }
    }

    /**
     * Try to take a concurrency slot for $ip under the global + per-IP caps, atomically. BEGIN
     * IMMEDIATE grabs the write lock so the inline stale-slot reap, both counts and the insert all see
     * one consistent snapshot — the caps are hard ceilings with no check-then-act race even under a
     * burst. Fails closed to FULL on lock contention or any storage error (never WON, never a throw).
     *
     * @return array{status:string,slot:int|null} slot is the tarpit_slot row id on WON, else null
     */
    public function acquire(string $ip): array
    {
        $db = null;
        try {
            $db = $this->db();
            $now = ($this->clock)();
            $db->exec('BEGIN IMMEDIATE');

            // SHOULD-FIX 5: self-reap stale slots INLINE, before the count, so a crashed holder
            // self-clears within one TTL regardless of when the retention cron next runs.
            $cut = gmdate('c', $now - max(1, $this->slotTtlSecs));
            $db->prepare('DELETE FROM tarpit_slot WHERE started_at < :c')->execute([':c' => $cut]);

            $global = (int) $db->query('SELECT COUNT(*) FROM tarpit_slot')->fetchColumn();
            if ($global >= max(1, $this->maxConcurrent)) {
                $db->exec('COMMIT');

                return ['status' => self::FULL, 'slot' => null];
            }

            $perIpStmt = $db->prepare('SELECT COUNT(*) FROM tarpit_slot WHERE ip = :ip');
            $perIpStmt->execute([':ip' => $ip]);
            if ((int) $perIpStmt->fetchColumn() >= max(1, $this->maxPerIp)) {
                $db->exec('COMMIT');

                return ['status' => self::PER_IP_FULL, 'slot' => null];
            }

            $db->prepare('INSERT INTO tarpit_slot (ip, started_at) VALUES (:ip, :t)')
                ->execute([':ip' => $ip, ':t' => gmdate('c', $now)]);
            $slot = (int) $db->lastInsertId();
            $db->exec('COMMIT');

            return ['status' => self::WON, 'slot' => $slot];
        } catch (Throwable $e) {
            if ($db !== null) {
                try {
                    $db->exec('ROLLBACK');
                } catch (Throwable $e2) {
                    // no active transaction to roll back
                }
            }

            return ['status' => self::FULL, 'slot' => null]; // fail-closed
        }
    }

    /** Free a held slot. No-op on null (guard() returned null => nothing was taken). Best-effort. */
    public function release(?int $slotId): void
    {
        if ($slotId === null) {
            return;
        }
        try {
            $this->db()->prepare('DELETE FROM tarpit_slot WHERE id = :id')->execute([':id' => $slotId]);
        } catch (Throwable $e) {
            // best-effort; the inline reaper + retention cron clean up anything left behind
        }
    }

    /** Reclaim slots left by a crashed holder. Returns rows cleared. TTL defaults to the SHORT slot TTL. */
    public function reap(?int $secs = null): int
    {
        try {
            $ttl = $secs ?? $this->slotTtlSecs;
            $st = $this->db()->prepare('DELETE FROM tarpit_slot WHERE started_at < :c');
            $st->execute([':c' => gmdate('c', ($this->clock)() - $ttl)]);

            return $st->rowCount();
        } catch (Throwable $e) {
            return 0; // best-effort
        }
    }

    public function inflightCount(): int
    {
        try {
            return (int) $this->db()->query('SELECT COUNT(*) FROM tarpit_slot')->fetchColumn();
        } catch (Throwable $e) {
            return 0;
        }
    }

    /** Slots this IP currently holds (test/telemetry helper). */
    public function inflightForIp(string $ip): int
    {
        try {
            $st = $this->db()->prepare('SELECT COUNT(*) FROM tarpit_slot WHERE ip = :ip');
            $st->execute([':ip' => $ip]);

            return (int) $st->fetchColumn();
        } catch (Throwable $e) {
            return 0;
        }
    }

    /**
     * Add a tarpit response's cost to the current hour bucket for $ip (bytes emitted, server wall-ms,
     * pages served). Upsert on (ip, hour_bucket); best-effort — a lost charge only under-counts, and
     * the concurrency + fail-closed guards are the hard controls. Callers pass the values guard()'s
     * slot lifetime produced.
     */
    public function charge(string $ip, int $bytes, int $wallMs, int $pages = 1): void
    {
        try {
            $this->db()->prepare(
                'INSERT INTO tarpit_ledger (ip, hour_bucket, bytes, wall_ms, pages) VALUES (:ip, :h, :b, :w, :p)
                 ON CONFLICT(ip, hour_bucket) DO UPDATE SET bytes = bytes + :b, wall_ms = wall_ms + :w, pages = pages + :p'
            )->execute([
                ':ip' => $ip,
                ':h' => $this->hourBucket(),
                ':b' => max(0, $bytes),
                ':w' => max(0, $wallMs),
                ':p' => max(0, $pages),
            ]);
        } catch (Throwable $e) {
            // best-effort
        }
    }

    /**
     * True if $ip has spent its per-IP hourly budget (bytes / wall-ms / pages) OR the global bytes/hr
     * aggregate is exhausted, for the current hour bucket. Fails CLOSED (returns true) on any storage
     * error: if the budget cannot be verified, treat it as spent and shed.
     */
    public function overBudget(string $ip): bool
    {
        try {
            $bucket = $this->hourBucket();
            $db = $this->db();

            $st = $db->prepare(
                'SELECT COALESCE(SUM(bytes),0) b, COALESCE(SUM(wall_ms),0) w, COALESCE(SUM(pages),0) p
                 FROM tarpit_ledger WHERE ip = :ip AND hour_bucket = :h'
            );
            $st->execute([':ip' => $ip, ':h' => $bucket]);
            $row = $st->fetch(PDO::FETCH_ASSOC) ?: ['b' => 0, 'w' => 0, 'p' => 0];
            if ((int) $row['b'] >= $this->bytesPerIpHr) {
                return true;
            }
            if ((int) $row['w'] >= $this->wallPerIpHrMs) {
                return true;
            }
            if ((int) $row['p'] >= $this->pagesPerIpHr) {
                return true;
            }

            $g = $db->prepare('SELECT COALESCE(SUM(bytes),0) FROM tarpit_ledger WHERE hour_bucket = :h');
            $g->execute([':h' => $bucket]);

            return (int) $g->fetchColumn() >= $this->globalBytesHr;
        } catch (Throwable $e) {
            return true; // fail-closed
        }
    }

    /** Drop ledger buckets older than $keepHours (retention). Returns rows removed. */
    public function pruneLedger(int $keepHours = 3): int
    {
        try {
            $st = $this->db()->prepare('DELETE FROM tarpit_ledger WHERE hour_bucket < :c');
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
        $db = Sqlite::open($this->dbPath);
        $db->exec(
            'CREATE TABLE IF NOT EXISTS tarpit_slot (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, started_at TEXT
            )'
        );
        $db->exec('CREATE INDEX IF NOT EXISTS idx_tarpit_slot_ip ON tarpit_slot(ip)');
        $db->exec('CREATE INDEX IF NOT EXISTS idx_tarpit_slot_started ON tarpit_slot(started_at)');
        $db->exec(
            'CREATE TABLE IF NOT EXISTS tarpit_ledger (
                ip TEXT, hour_bucket INTEGER, bytes INTEGER DEFAULT 0, wall_ms INTEGER DEFAULT 0,
                pages INTEGER DEFAULT 0, PRIMARY KEY (ip, hour_bucket)
            )'
        );

        return $this->db = $db;
    }
}
