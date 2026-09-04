<?php

declare(strict_types=1);

namespace Funnypot\App\Engagement;

/**
 * The operator read side of engagement metrics, separate from the write side so the dashboard
 * depends on the interface, not the SQLite store, and a no-op wiring still constructs. Everything
 * returned is a closed set of typed aggregates: counts, stages, bytes, measured server cost,
 * usage-availability and labelled estimates. Never raw hits, paths, bodies or evidence values, and
 * never an "actor" — episodes are pseudonymous groupings whose basis/confidence is part of the data.
 */
interface EngagementAnalytics
{
    /**
     * Aggregates over episodes that started at or after $sinceEpoch. Ratios use a documented
     * zero-denominator rule: null (rendered as an em dash), never 0 or a division error. Unknown
     * LLM usage stays null.
     *
     * @return array<string,mixed>
     */
    public function summary(int $sinceEpoch): array;

    /**
     * The most recent episodes (bounded by $limit, itself capped) as per-episode summaries — a
     * detail view, not a rollup dimension. The episode id is exposed only as a short label.
     *
     * @return list<array<string,mixed>>
     */
    public function recent(int $sinceEpoch, int $limit): array;

    /** The fixed-name saturating health counters and size gauges. @return array<string,int|bool|string> */
    public function health(): array;
}
