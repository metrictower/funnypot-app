<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Attrition;

/** A rendered NDJSON artifact: the exact bytes, their length, and their lowercase SHA-256 (FP-0272 §6.5). */
final class RenderedAttritionArtifact
{
    public function __construct(
        public readonly string $body,
        public readonly int $length,
        public readonly string $sha256,
    ) {
    }
}
