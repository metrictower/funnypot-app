<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Attrition;

/** The outcome of one bounded expired-journey prune pass (FP-0272 §7). */
final class PruneResult
{
    public function __construct(
        public readonly int $journeysRemoved,
        public readonly int $rowsRemoved,
    ) {
    }
}
