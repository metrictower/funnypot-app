<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

/**
 * What the served-key index can answer: whether a fact some generator serves (a key, or a host
 * settings.py names) is indexed, and whether the index covers every generator yet. While it is
 * incomplete, a fact it does not hold may still be served, so answers about it stay transient.
 */
interface KeyIndexView
{
    /** @param string $kind aws, asia, stripe or host */
    public function contains(string $kind, string $value): bool;

    /** The keyed hash a fact is indexed under (24 hex characters); no raw value is ever stored. */
    public function hashOf(string $kind, string $value): string;

    public function containsHash(string $hashHex): bool;

    public function complete(): bool;

    /** Run at most one bounded build step, never waiting for a lock. */
    public function advance(int $now): void;
}
