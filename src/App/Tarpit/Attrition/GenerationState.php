<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Attrition;

/** The committed generation row (FP-0272 §6.4). */
final class GenerationState
{
    public function __construct(
        public readonly string $generationId,
        public readonly int $generation,
    ) {
    }
}
