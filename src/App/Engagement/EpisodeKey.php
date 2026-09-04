<?php

declare(strict_types=1);

namespace Funnypot\App\Engagement;

use InvalidArgumentException;

/**
 * Verified, keyed episode evidence — what the store groups on. Produced only by
 * {@see EpisodeResolver}, after the raw evidence has been verified and reduced to an install-local
 * HMAC digest, so the store never sees a handle, an IP or a user agent. The confidence is fixed by
 * the basis and cannot be raised later.
 */
final class EpisodeKey
{
    public function __construct(
        public string $basis,
        public string $confidence,
        public string $digest,
    ) {
        if (!IdentityBasis::isValid($basis) || IdentityBasis::confidenceOf($basis) !== $confidence) {
            throw new InvalidArgumentException('basis/confidence mismatch');
        }
        if (preg_match('/^[a-f0-9]{32,64}$/', $digest) !== 1) {
            throw new InvalidArgumentException('digest is not a keyed id');
        }
    }
}
