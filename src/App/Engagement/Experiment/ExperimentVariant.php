<?php

declare(strict_types=1);

namespace Funnypot\App\Engagement\Experiment;

/**
 * One immutable arm of an experiment: an ordered id, a positive integer weight, and the code-owned
 * implementation version that renders it. Part of an ExperimentDefinition's semantic bytes (FP-0311 §2.1).
 */
final class ExperimentVariant
{
    public function __construct(
        public readonly string $id,
        public readonly int $weight,
        public readonly string $implementationId
    ) {
    }
}
