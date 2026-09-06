<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Attrition;

/**
 * The bounded attrition state contract (FP-0272 §7). Implementations persist only closed 32-hex ids,
 * closed revisions/generations, and integer times/counts/costs — never a raw handle, nonce, target, IP,
 * body, or generated artifact. Every method is fail-fast: a lock, cap, clock, or storage fault returns
 * null / a no-op result rather than throwing, retrying, or sleeping, so a public request degrades to the
 * ordinary 404 and never a slow path.
 */
interface AttritionStore
{
    /** Idempotently load-or-create the job for one entry; null on cap/expiry/fault. */
    public function createJob(JobCandidate $candidate, int $now): ?JobState;

    /** Saturating poll increment (…→9); null when the job is missing/expired or on a lock/fault. */
    public function advancePoll(string $jobId, int $now): ?PollState;

    /** Read-only manifest eligibility; null when not (yet) eligible or on fault. */
    public function prepareManifest(string $manifestId, int $now): ?ManifestCandidate;

    /** Idempotently insert one generation row; null on ineligibility recheck/cap/fault. */
    public function commitManifest(ManifestCommit $commit, int $now): ?GenerationState;

    /** Read-only artifact authorization; null when the generation row is missing/expired or on fault. */
    public function prepareArtifact(string $artifactId, int $now): ?ArtifactCandidate;

    /** Commit the 0→1→2 (saturating) fetch transition; null on lock/fault. */
    public function commitArtifactFetch(string $artifactId, int $now): ?FetchTransition;

    /** Reclaim at most $limit expired journeys (cascade children), reconciling the quota. */
    public function pruneExpired(int $limit, int $now): PruneResult;

    /** Best-effort WAL checkpoint + incremental vacuum for retention/operator maintenance. */
    public function maintain(): void;

    /** Main db + WAL size in bytes (O(1)); the emergency physical-size guard reads this. */
    public function physicalBytes(): int;
}
