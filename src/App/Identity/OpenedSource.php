<?php

declare(strict_types=1);

namespace Funnypot\App\Identity;

/**
 * A source file the {@see SourceOpener} validated: its still-open read handle, the bytes read
 * through that handle, and the attestation of how it was opened. The handle is deliberately kept
 * open so a consumer can fstat/re-read the very inode that was validated instead of reopening a path.
 *
 * @internal
 */
final class OpenedSource
{
    /** @param resource $handle */
    public function __construct(
        public readonly mixed $handle,
        public readonly string $bytes,
        public readonly SourceOpenAttestation $attestation,
    ) {
    }

    public function sha256(): string
    {
        return hash('sha256', $this->bytes);
    }
}
