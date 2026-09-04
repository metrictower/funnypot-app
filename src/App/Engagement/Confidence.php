<?php

declare(strict_types=1);

namespace Funnypot\App\Engagement;

/** Closed confidence vocabulary for an episode's identity basis ({@see IdentityBasis::confidenceOf()}). */
final class Confidence
{
    public const HIGH = 'high';
    public const MEDIUM = 'medium';
    public const LOW = 'low';

    /** @return list<string> */
    public static function all(): array
    {
        return [self::HIGH, self::MEDIUM, self::LOW];
    }

    public static function isValid(string $confidence): bool
    {
        return in_array($confidence, self::all(), true);
    }
}
