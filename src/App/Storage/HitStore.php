<?php

declare(strict_types=1);

namespace Funnypot\App\Storage;

/**
 * The app's hit store: every HTTP probe, decoy download and TCP-protocol event the honeypot sees
 * is appended here, and the dashboard reads its live feed, paging and aggregates back out.
 *
 * This is the seam the data-layer decision rests on (docs/DATA-LAYER-DECISION.md): the single-box
 * build uses {@see SqliteHitStore}; a fleet build can drop in a Postgres backend behind the same
 * interface without touching callers.
 */
interface HitStore
{
    /**
     * Append one hit. Attacker-supplied fields (path/body) may carry raw binary bytes from the
     * protocol honeypots; the implementation makes them UTF-8 safe before storing.
     *
     * @param array<string,mixed> $entry
     */
    public function append(array $entry): void;

    /**
     * Rows appended since the client's opaque cursor, oldest-first (the client prepends them
     * newest-on-top). `reset` tells the client to clear and reload from scratch. $filters narrows
     * the rows (e.g. method=SSH + event=command for "all SSH commands"); the cursor still tracks
     * the newest row overall so live polling keeps working under a filter.
     *
     * @param array<string,mixed> $filters
     * @return array{cursor:int,reset:bool,rows:array<int,array<string,mixed>>}
     */
    public function delta(int $cursor, array $filters = []): array;

    /**
     * A page of older history, newest-first, skipping the newest $skip, narrowed by $filters.
     *
     * @param array<string,mixed> $filters
     * @return array{rows:array<int,array<string,mixed>>,more:bool}
     */
    public function older(int $skip, array $filters = []): array;

    /** @return array<string,int> total / detections / served / ips / harvested */
    public function stats(): array;

    /**
     * Aggregate widgets: top talker IPs, top source countries, top fired templates, hourly histogram.
     *
     * @return array<string,array<int,array<string,mixed>>>
     */
    public function widgets(): array;

    /** Retention: keep only the newest $keep events. */
    public function prune(int $keep): void;

    /** Delete all captured data. */
    public function clear(): void;

    /** Backfill from the JSON-lines export log (the migration source). Returns rows imported. */
    public function import(): int;

    /**
     * How many distinct paths this IP has probed recently — the signal for the LLM gate's per-IP
     * velocity check (a bulk dirbuster sweeps many distinct paths fast).
     *
     * @return array{recent:int,extended:int} distinct paths in the last 60s and last 10min
     */
    public function probeVelocity(string $ip): array;

    /**
     * How many hits this IP has logged with the given event in the last $sinceSeconds — the signal
     * behind the AI-API "believable first, troll after" budget (a fresh IP gets a few real answers,
     * then degrades). Windowed so the budget refreshes after a quiet gap, like a real session.
     */
    public function recentEventCount(string $ip, string $event, int $sinceSeconds): int;

    /** Pin an IP to plain-404-only (the LLM gate's bulk-scan cooldown) for $hours. */
    public function flagBulkScan(string $ip, int $hours): void;

    /** Is this IP currently pinned as a bulk scanner? */
    public function isBulkFlagged(string $ip): bool;
}
