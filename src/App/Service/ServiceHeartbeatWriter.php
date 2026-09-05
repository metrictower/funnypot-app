<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

/**
 * The heartbeat-write seam the supervisor drives. Production is {@see ServiceStatusPublisher}; a test
 * spy records the call order so ordering invariants (first heartbeat before first fork, persistent
 * manifest before heartbeat) can be asserted without a real file.
 */
interface ServiceHeartbeatWriter
{
    /** @param array<string,string> $processHealth */
    public function publish(EffectiveExposureArtifact $artifact, string $state, string $acceptanceMode, array $processHealth, int $statusRevision, ?int $writtenAt = null): void;
}
