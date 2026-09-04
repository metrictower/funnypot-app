<?php

declare(strict_types=1);

namespace Funnypot\App\Engagement;

use Funnypot\App\Config\AppConfig;

/**
 * The bounded-storage contract of the engagement store, clamped so no config value can unbound it.
 * Per-episode caps (events, artifacts, retained bytes) and global ceilings (rows, retained bytes)
 * are enforced inline on every write; the age ceiling is applied by the retention pass and is never
 * longer than the source hit retention nor 30 days.
 */
final class EngagementCaps
{
    public const MAX_RETAIN_DAYS = 30;

    public function __construct(
        public int $idleGapS = 600,
        public int $lifetimeS = 7200,
        public int $maxEventsPerEpisode = 2000,
        public int $maxArtifactsPerEpisode = 256,
        public int $maxBytesPerEpisode = 2 * 1024 * 1024,
        public int $globalMaxRows = 250000,
        public int $globalMaxBytes = 256 * 1024 * 1024,
        public int $retainDays = self::MAX_RETAIN_DAYS,
    ) {
        $this->idleGapS = max(60, min(1800, $idleGapS));
        $this->lifetimeS = max(600, min(21600, $lifetimeS));
        $this->maxEventsPerEpisode = max(1, min(100000, $maxEventsPerEpisode));
        $this->maxArtifactsPerEpisode = max(1, min(10000, $maxArtifactsPerEpisode));
        $this->maxBytesPerEpisode = max(4096, min(64 * 1024 * 1024, $maxBytesPerEpisode));
        $this->globalMaxRows = max(1000, min(5000000, $globalMaxRows));
        // Config can never go below 1 MiB (the MB knob's floor is 1); this lower floor only matters
        // for direct construction, so a test can reach the byte ceiling in a few hundred rows.
        $this->globalMaxBytes = max(64 * 1024, min(4096 * 1024 * 1024, $globalMaxBytes));
        $this->retainDays = max(1, min(self::MAX_RETAIN_DAYS, $retainDays));
    }

    public static function fromConfig(AppConfig $c): self
    {
        return new self(
            $c->engagementIdleGapS,
            $c->engagementLifetimeS,
            $c->engagementMaxEvents,
            $c->engagementMaxArtifacts,
            $c->engagementBytesPerEpMb * 1024 * 1024,
            $c->engagementGlobalRows,
            $c->engagementGlobalBytesMb * 1024 * 1024,
            self::retainCeiling($c->engagementRetainDays, $c->retainDays),
        );
    }

    /**
     * Engagement rows never outlive the source hits: the ceiling is the hit retention when one is
     * set (0 = unbounded hits, so the 30-day cap applies alone), and never more than 30 days.
     */
    public static function retainCeiling(int $engagementDays, int $hitRetainDays): int
    {
        $ceiling = $hitRetainDays > 0 ? min($hitRetainDays, self::MAX_RETAIN_DAYS) : self::MAX_RETAIN_DAYS;

        return max(1, min($engagementDays, $ceiling));
    }
}
