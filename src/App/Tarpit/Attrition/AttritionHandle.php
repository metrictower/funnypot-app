<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Attrition;

/**
 * One verified attrition handle: the typed result of decoding a 117-byte token (FP-0272 §5). It
 * carries only the kind, the inherited issue/expiry epoch seconds, and the in-memory 16-byte opaque
 * safety/quota subject plus the 16-byte nonce. It never holds the raw token, the peer address, or the
 * MAC, and {@see __debugInfo()} hides the two private byte fields so a var_dump/log line can never
 * spill them.
 *
 * The subject is a keyed partition of the already-resolved peer, not identity: it exists only so
 * unrelated clients do not advance one shared job and so the per-journey caps have a real scope.
 */
final class AttritionHandle
{
    public const KIND_ENTRY = 'e';
    public const KIND_JOB = 'j';
    public const KIND_MANIFEST = 'm';
    public const KIND_ARTIFACT = 'a';

    public function __construct(
        public readonly string $kind,
        public readonly int $issuedAt,
        public readonly int $expiresAt,
        public readonly string $subject,
        public readonly string $nonce,
    ) {
    }

    /** @return array<string,int|string> the private subject/nonce bytes are deliberately excluded */
    public function __debugInfo(): array
    {
        return ['kind' => $this->kind, 'issuedAt' => $this->issuedAt, 'expiresAt' => $this->expiresAt];
    }
}
