<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Attrition;

/**
 * The read-only eligibility result for a manifest request (FP-0272 §6.4). `alreadyCommitted` marks a
 * repeat fetch of an existing generation row (return byte-identical bytes, no new row); otherwise this is
 * the next eligible generation to render and commit. `rendererRevision` is the current revision for a new
 * generation 0 and the inherited revision for a later generation, so an in-flight journey is never
 * silently reinterpreted by a newer renderer.
 */
final class ManifestCandidate
{
    public function __construct(
        public readonly string $jobId,
        public readonly int $generation,
        public readonly string $rendererRevision,
        public readonly int $expiresAt,
        public readonly bool $alreadyCommitted,
    ) {
    }
}
