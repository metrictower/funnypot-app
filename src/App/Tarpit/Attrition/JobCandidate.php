<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Attrition;

/**
 * The controller-derived inputs for an idempotent job create (FP-0272 §6.2). Every id is a 32-hex
 * install-local HMAC the codec produced; no raw handle, nonce, peer, or target is present.
 */
final class JobCandidate
{
    public function __construct(
        public readonly string $journeyId,
        public readonly string $entryId,
        public readonly string $jobId,
        public readonly string $firstManifestId,
        public readonly string $revision,
        public readonly int $expiresAt,
    ) {
    }
}
