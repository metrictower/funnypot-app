<?php

declare(strict_types=1);

namespace Funnypot\App\Storage;

/**
 * The read-side analytics API, kept SEPARATE from {@see HitStore} on purpose.
 *
 * `HitStore` has three lightweight test doubles (DownloadRouterTest, ConsoleRouterTest,
 * HomeControllerTest); forcing rollup/aggregation methods onto it would make every one of them
 * implement SQLite-specific analytics, and would tie any future Postgres backend to this rollup
 * scheme. So the aggregation surface lives here and is implemented only by the store that actually
 * owns the rollup tables ({@see SqliteHitStore}).
 *
 * The design (docs/DATA-LAYER-DECISION.md, FP-0243 spec §5): a background worker folds the raw
 * `hits` table into a small `rollup` table on a timer via {@see foldRollups()}, and the read
 * methods below serve the operator analytics view from that small table in O(buckets) — flat in
 * total event volume — instead of re-scanning the whole `hits` table on every dashboard tick.
 * `topN()` and the unique/new-vs-returning half of `ataglance()` stay raw GROUP BYs over the
 * retention-capped `hits` table (their cardinality is unbounded or non-additive, so they cannot be
 * summed from per-bucket counts); they are only ever called by the analytics endpoint, never by the
 * 3-second live feed poll.
 */
interface AnalyticsStore
{
    /**
     * The worker pass. Reads up to $batch new `hits` rows since the stored watermark, aggregates
     * them into minute/hour/day rollup buckets (all derived from the same batch — never by
     * re-reading prunable minute rows), applies the top-K cardinality cap, prunes rollup rows past
     * retention, and advances the watermark — all in ONE transaction, so it is exactly-once (a
     * crash before commit rolls the whole pass back and the next pass reprocesses the same rows
     * with no double count). Returns the number of raw hit rows folded this pass (0 when drained).
     * The worker loops until it returns 0.
     */
    public function foldRollups(int $batch): int;

    /**
     * One aggregate breakdown for $dim over buckets at or after $sinceEpoch at granularity $gran
     * ('m'|'h'|'d'), ordered by count desc. Reads the small rollup table only.
     *
     * @return array<int,array{val:string,n:int,matched:int,served:int}>
     */
    public function breakdown(string $dim, int $sinceEpoch, string $gran = 'h'): array;

    /**
     * Events-over-time: for each requested value of $dim, the per-bucket counts at or after
     * $sinceEpoch at granularity $gran ('m'|'h'|'d'), buckets ascending. Keyed by value so a
     * multi-series chart can plot one line per protocol/tool/etc.
     *
     * @param array<int,string> $vals
     * @return array<string,array<int,array{bucket:int,n:int}>>
     */
    public function series(string $dim, array $vals, int $sinceEpoch, string $gran = 'm'): array;

    /**
     * Top-$limit values for a HIGH-cardinality dimension ('ip'|'asn'|'path'|'tool'|'cc'), computed
     * on demand as a single indexed GROUP BY over the retention-capped raw `hits` table (these are
     * unbounded or non-additive, so they are not pre-aggregated). $sinceEpoch bounds the window.
     *
     * @return array<int,array{val:string,n:int}>
     */
    public function topN(string $dim, int $limit, int $sinceEpoch): array;

    /**
     * At-a-glance tiles over the last $windowS seconds: event rate (from the minute rollups),
     * plus unique-IP and new-vs-returning counts (raw, windowed — a union of per-bucket sets is not
     * a sum, so these cannot come from the rollups).
     *
     * @return array{window_s:int,events:int,rate:float,unique_ips:int,new:int,returning:int}
     */
    public function ataglance(int $windowS): array;
}
