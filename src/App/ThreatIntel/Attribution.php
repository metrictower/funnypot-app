<?php

declare(strict_types=1);

namespace Funnypot\App\ThreatIntel;

/**
 * The result of scanner attribution: a closed-vocabulary tool name (the only value ever persisted),
 * its confidence, and an optional shape-validated version.
 *
 * $tool is always one of the pack's fixed labels, never attacker bytes. $version may be captured for a
 * version-specific tell but is deliberately NOT persisted in V1: a spoofable version string must not
 * enter the bounded `tool` rollup dimension, so it lives only here for a future consumer.
 */
final class Attribution
{
    public function __construct(
        public string $tool,
        public string $confidence,
        public ?string $version = null,
    ) {
    }
}
