<?php

declare(strict_types=1);

namespace Funnypot\App\Engagement;

/**
 * The closed journey-stage vocabulary, ordered shallow to deep. An episode's "deepest observed
 * stage" is the max {@see rank()} over its events; the rank order is the only meaning the numbers
 * carry. Producers map their own notion of depth onto these: a bare labyrinth entry is DISCOVER, a
 * deeper labyrinth page is ENUMERATE, a polluter export is COLLECT. The later stages are reserved
 * for future issued-lure seams.
 */
final class Stage
{
    public const DISCOVER = 'discover';
    public const ENUMERATE = 'enumerate';
    public const AUTH = 'auth';
    public const ACCESS = 'access';
    public const COLLECT = 'collect';
    public const EXECUTE_ATTEMPT = 'execute_attempt';
    public const PERSIST_ATTEMPT = 'persist_attempt';
    public const VERIFY = 'verify';
    public const EXIT = 'exit';

    /** @return list<string> shallow to deep */
    public static function all(): array
    {
        return [
            self::DISCOVER, self::ENUMERATE, self::AUTH, self::ACCESS, self::COLLECT,
            self::EXECUTE_ATTEMPT, self::PERSIST_ATTEMPT, self::VERIFY, self::EXIT,
        ];
    }

    public static function isValid(string $stage): bool
    {
        return in_array($stage, self::all(), true);
    }

    /** 1-based depth rank; 0 for an unknown stage (never stored — the event rejects it first). */
    public static function rank(string $stage): int
    {
        $i = array_search($stage, self::all(), true);

        return $i === false ? 0 : $i + 1;
    }

    /** The stage for a rank, or null when out of range. */
    public static function fromRank(int $rank): ?string
    {
        return self::all()[$rank - 1] ?? null;
    }
}
