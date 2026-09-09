<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Attrition;

/** The read-only authorization for an artifact fetch: which generation/revision to render (FP-0272 §6.5). */
final class ArtifactCandidate
{
    public function __construct(
        public readonly string $jobId,
        public readonly int $generation,
        public readonly string $rendererRevision,
        public readonly int $expiresAt,
    ) {
    }
}
