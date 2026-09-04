<?php

declare(strict_types=1);

namespace Funnypot\App\Engagement;

/**
 * The closed engagement-event vocabulary. Every stored event names exactly one of these; a producer
 * cannot invent a kind, so an attacker-controlled string can never become a row key or a rollup
 * dimension.
 */
final class EventKind
{
    public const LURE_ISSUED = 'lure_issued';
    public const LURE_FOLLOWED = 'lure_followed';
    public const ARTIFACT_ISSUED = 'artifact_issued';
    public const ARTIFACT_FETCHED = 'artifact_fetched';
    public const ARTIFACT_REUSED = 'artifact_reused';
    public const JOB_POLLED = 'job_polled';
    public const TOOL_TURN = 'tool_turn';
    public const STAGE_ADVANCED = 'stage_advanced';

    /** @return list<string> */
    public static function all(): array
    {
        return [
            self::LURE_ISSUED, self::LURE_FOLLOWED, self::ARTIFACT_ISSUED, self::ARTIFACT_FETCHED,
            self::ARTIFACT_REUSED, self::JOB_POLLED, self::TOOL_TURN, self::STAGE_ADVANCED,
        ];
    }

    public static function isValid(string $kind): bool
    {
        return in_array($kind, self::all(), true);
    }
}
