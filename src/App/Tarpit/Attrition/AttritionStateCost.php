<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Attrition;

/**
 * The deterministic logical cost of one attrition state row (FP-0272 §7). This is an ACCOUNTING number,
 * not real disk usage: a fixed per-table overhead plus the bounded serialized field lengths, so the
 * singleton quota and per-journey counters can be reconciled in the same transaction as an insert/delete
 * and every runtime cap check stays O(1) (a counter read, never a COUNT/SUM scan). Rows store only closed
 * 32-hex ids, closed revisions, and integers, so each row's cost is a fixed constant.
 */
final class AttritionStateCost
{
    public const JOURNEY = 256;
    public const JOB = 384;
    public const GENERATION = 448;
}
