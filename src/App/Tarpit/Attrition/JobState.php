<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Attrition;

/** The committed job row after a create — the poll ordinal starts at 0 (FP-0272 §6.2). */
final class JobState
{
    public function __construct(
        public readonly string $jobId,
        public readonly int $pollCount,
    ) {
    }
}
