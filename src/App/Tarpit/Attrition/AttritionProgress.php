<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Attrition;

/**
 * The sole progress/Retry-After authority for the fake async export (FP-0272 §6.3). Nine immutable rows,
 * mapped from the poll ordinal. Ordinal 9 is terminal: {@see forPoll()} clamps anything at or beyond it to
 * the `ready` row, which carries no retry guidance. No clock or background task advances progress — only a
 * client poll does — and no row implies any real work was performed.
 */
final class AttritionProgress
{
    /** @var array<int,array{state:string,progress:int,retry:?int}> */
    private const ROWS = [
        1 => ['state' => 'queued', 'progress' => 4, 'retry' => 2],
        2 => ['state' => 'queued', 'progress' => 9, 'retry' => 3],
        3 => ['state' => 'discovering', 'progress' => 18, 'retry' => 3],
        4 => ['state' => 'collecting', 'progress' => 34, 'retry' => 4],
        5 => ['state' => 'collecting', 'progress' => 52, 'retry' => 4],
        6 => ['state' => 'serializing', 'progress' => 68, 'retry' => 5],
        7 => ['state' => 'indexing', 'progress' => 81, 'retry' => 3],
        8 => ['state' => 'checksumming', 'progress' => 93, 'retry' => 2],
        9 => ['state' => 'ready', 'progress' => 99, 'retry' => null],
    ];

    /**
     * The progress row for a poll ordinal. Ordinals below 1 clamp to row 1; at or above 9 return the
     * terminal `ready` row (no Retry-After).
     *
     * @return array{state:string,progress:int,retry:?int}
     */
    public static function forPoll(int $poll): array
    {
        $ordinal = max(1, min(AttritionLimits::POLLS, $poll));

        return self::ROWS[$ordinal];
    }

    public static function isTerminal(int $poll): bool
    {
        return $poll >= AttritionLimits::POLLS;
    }
}
