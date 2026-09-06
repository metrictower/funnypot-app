<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Attrition;

/**
 * The committed fetch transition for an artifact (FP-0272 §6.5). `isFirst` is the 0→1 transition; a later
 * fetch (1→2, then saturating) is a reuse. This distinction only feeds observation and gates the next
 * generation's eligibility — it never changes the served bytes.
 */
final class FetchTransition
{
    public function __construct(public readonly bool $isFirst)
    {
    }
}
