<?php

declare(strict_types=1);

namespace Funnypot\App\Engagement;

use Funnypot\App\Http\PolluterController;

/**
 * Stable, code-owned lure-definition ids. A lure id names WHAT was served (a definition), never WHO
 * fetched it — it is not identity and carries no confidence. Kept here as one closed set so a
 * controller never derives an id from request text and the dashboard can label every id it sees.
 */
final class LureId
{
    public const LABYRINTH = 'labyrinth';
    public const POLLUTER_CONFIG = 'polluter_config';
    public const POLLUTER_LOG = 'polluter_log';
    public const POLLUTER_HOSTILE = 'polluter_hostile';
    public const POLLUTER_SHADOW = 'polluter_shadow';

    /** @return list<string> */
    public static function all(): array
    {
        return [
            self::LABYRINTH, self::POLLUTER_CONFIG, self::POLLUTER_LOG, self::POLLUTER_HOSTILE, self::POLLUTER_SHADOW,
        ];
    }

    public static function isValid(string $id): bool
    {
        return in_array($id, self::all(), true);
    }

    /** The polluter lure id for one of its four fixed paths; null for anything else. */
    public static function forPolluterPath(string $path): ?string
    {
        switch ($path) {
            case PolluterController::CONFIG_PATH:
                return self::POLLUTER_CONFIG;
            case PolluterController::LOG_PATH:
                return self::POLLUTER_LOG;
            case PolluterController::HOSTILE_PATH:
                return self::POLLUTER_HOSTILE;
            case PolluterController::SHADOW_PATH:
                return self::POLLUTER_SHADOW;
            default:
                return null;
        }
    }
}
