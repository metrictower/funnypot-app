<?php

declare(strict_types=1);

namespace Funnypot\App\Analytics;

/**
 * FP-0361 — a per-source attacker "heat" score: a decaying, weighted count of ANOMALOUS events (decoy
 * trips, honeytoken hits, attack-classified requests, repeated 4xx) that passively drives tarpit
 * aggressiveness for hot sources and enriches the hit-store/mainnet threat-intel confidence. Inspired by
 * BunkerWeb's Bad-Behavior sliding-window score — but the BAN action is anti-thetical to a honeypot, so
 * this keeps only the SCORE; it NEVER blocks, challenges, or changes served bytes.
 *
 * Exponential time decay (configurable half-life): each observe/read first decays the stored heat by the
 * elapsed time, so a source that goes quiet cools toward 0 and an active one accrues. Pure of I/O
 * (in-memory per-source map, injected clock), LRU-bounded (MAX_SOURCES) so it can't grow unbounded under
 * a source-rotation flood. The score is a bounded float; it is NEVER emitted as a raw per-IP label into a
 * metric (cardinality + PII) — only a coarse tier / a per-record enrichment field.
 */
final class AttackerHeat
{
    /** Event weights — a honeytoken hit is the strongest signal, a lone 4xx the weakest. */
    public const WEIGHTS = [
        'honeytoken' => 5.0,
        'attack_class' => 3.0,
        'decoy' => 1.0,
        'http_4xx' => 0.5,
    ];

    /** Coarse tiers for the tarpit (never a raw score label): cold < warm < hot < scalding. */
    private const TIER_WARM = 3.0;
    private const TIER_HOT = 8.0;
    private const TIER_SCALDING = 20.0;

    private const MAX_SOURCES = 4096;
    private const MAX_HEAT = 1000.0; // clamp so a relentless source can't overflow

    /** @var array<string, array{heat: float, last: float}> */
    private array $sources = [];

    /** @var callable():float */
    private $clock;

    public function __construct(
        private float $halfLifeSecs = 300.0,
        ?callable $clock = null
    ) {
        $this->clock = $clock ?? static fn (): float => microtime(true);
    }

    /**
     * Record an anomalous event for $source, returning the new (decayed + incremented) heat. An unknown
     * event type contributes 0 (no-op weight) so a caller typo never silently inflates the score.
     */
    public function observe(string $source, string $eventType): float
    {
        $now = ($this->clock)();
        $this->ensure($source, $now);
        $heat = $this->decayed($source, $now) + (self::WEIGHTS[$eventType] ?? 0.0);
        $heat = min($heat, self::MAX_HEAT);
        $this->sources[$source]['heat'] = $heat;
        $this->sources[$source]['last'] = $now;

        return $heat;
    }

    /** The current decayed heat for $source (0.0 if untracked). Does not mutate. */
    public function heat(string $source): float
    {
        if (!isset($this->sources[$source])) {
            return 0.0;
        }

        return $this->decayed($source, ($this->clock)());
    }

    /** Coarse tier for the tarpit/enrichment: 'cold'|'warm'|'hot'|'scalding' (never the raw score). */
    public function tier(string $source): string
    {
        $h = $this->heat($source);
        if ($h >= self::TIER_SCALDING) {
            return 'scalding';
        }
        if ($h >= self::TIER_HOT) {
            return 'hot';
        }
        if ($h >= self::TIER_WARM) {
            return 'warm';
        }

        return 'cold';
    }

    public function isHot(string $source): bool
    {
        return $this->heat($source) >= self::TIER_HOT;
    }

    public function trackedSources(): int
    {
        return count($this->sources);
    }

    /** Heat after exponential decay to $now (does not write it back — callers that mutate set it). */
    private function decayed(string $source, float $now): float
    {
        $s = $this->sources[$source];
        $elapsed = max(0.0, $now - $s['last']);
        if ($elapsed === 0.0 || $this->halfLifeSecs <= 0.0) {
            return $s['heat'];
        }
        $factor = 2.0 ** (-($elapsed / $this->halfLifeSecs));

        return $s['heat'] * $factor;
    }

    private function ensure(string $source, float $now): void
    {
        if (isset($this->sources[$source])) {
            return;
        }
        // Evict the least-recently-OBSERVED source (reads don't refresh `last`): a quiet source cools and
        // is dropped first, which is the intended write-driven aging, not read-driven LRU.
        if (count($this->sources) >= self::MAX_SOURCES) {
            $oldestKey = null;
            $oldestAt = INF;
            foreach ($this->sources as $k => $v) {
                if ($v['last'] < $oldestAt) {
                    $oldestAt = $v['last'];
                    $oldestKey = $k;
                }
            }
            if ($oldestKey !== null) {
                unset($this->sources[$oldestKey]);
            }
        }
        $this->sources[$source] = ['heat' => 0.0, 'last' => $now];
    }
}
