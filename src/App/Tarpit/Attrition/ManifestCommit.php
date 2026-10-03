<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Attrition;

/**
 * The controller-derived inputs to commit one new generation row (FP-0272 §6.4). `nextManifestId` is null
 * for the final generation, which therefore carries no refresh link. Every id is a 32-hex install-local
 * HMAC; no raw handle, snapshot bytes, or checksum content is stored.
 */
final class ManifestCommit
{
    public function __construct(
        public readonly string $journeyId,
        public readonly string $jobId,
        public readonly string $generationId,
        public readonly int $generation,
        public readonly string $manifestId,
        public readonly string $artifactId,
        public readonly ?string $nextManifestId,
        public readonly string $rendererRevision,
        public readonly int $expiresAt,
        public readonly int $logicalBytes,
    ) {
    }
}
