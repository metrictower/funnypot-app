<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Attrition;

/** One poll transition: the ordinal 1..9 the row now holds; 9 is terminal and saturating (FP-0272 §6.3). */
final class PollState
{
    public function __construct(public readonly int $poll)
    {
    }
}
