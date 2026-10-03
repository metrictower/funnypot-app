<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Attrition;

use Funnypot\App\Config\AppConfig;

/**
 * The one place the attrition journey's numeric bounds live (FP-0272 §7). Two kinds of bound:
 *
 *  - CODE-OWNED HARD CAPS — poll count, generations per job, response byte caps, prune batch sizes,
 *    and the emergency physical-size ceiling. Editing one changes the journey's MEANING (a live token
 *    already promises exactly nine polls / three generations), so these are constants, never knobs.
 *  - CONFIGURED CEILINGS — TTL, jobs/generations per journey, global rows/bytes. These come from
 *    {@see AppConfig} but are RE-CLAMPED here so an extreme value that somehow reached the object (a
 *    direct constructor call, a future caller) still cannot unbound the store. MiB→bytes conversion
 *    happens once, at this boundary.
 */
final class AttritionLimits
{
    /** Polls before a job saturates at the terminal `ready` row. */
    public const POLLS = 9;
    /** Manifest/artifact generations per job: indices 0, 1, 2. */
    public const GENERATIONS = 3;
    /** Buffered response hard caps (bytes). */
    public const JSON_MAX_BYTES = 4096;
    public const MANIFEST_MAX_BYTES = 4096;
    public const ARTIFACT_MAX_BYTES = 32768;
    /** Expired-journey rows reclaimed inline before a mutation on the request path. */
    public const INLINE_PRUNE_ROWS = 128;
    /** Expired-journey rows reclaimed per maintenance (retention) pass. */
    public const MAINTENANCE_PRUNE_ROWS = 500;
    /** Emergency ceiling over main db + WAL; at/above it public mutations shed until maintenance recovers. */
    public const PHYSICAL_MAX_BYTES = 96 * 1024 * 1024;

    public readonly int $ttlS;
    public readonly int $maxJobsPerJourney;
    public readonly int $maxArtifactsPerJourney;
    public readonly int $globalRows;
    public readonly int $globalStateBytes;

    public function __construct(int $ttlS, int $maxJobs, int $maxArtifacts, int $globalRows, int $globalStateMb)
    {
        $this->ttlS = max(3600, min(21600, $ttlS));
        $this->maxJobsPerJourney = max(1, min(32, $maxJobs));
        $this->maxArtifactsPerJourney = max(3, min(64, $maxArtifacts));
        $this->globalRows = max(100, min(50000, $globalRows));
        $this->globalStateBytes = max(1, min(64, $globalStateMb)) * 1024 * 1024;
    }

    public static function fromConfig(AppConfig $c): self
    {
        return new self(
            $c->attritionTtl,
            $c->attritionMaxJobs,
            $c->attritionMaxArtifacts,
            $c->attritionGlobalRows,
            $c->attritionGlobalStateMb,
        );
    }
}
