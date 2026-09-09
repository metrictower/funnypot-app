<?php

declare(strict_types=1);

namespace Funnypot\App\Http;

/** Raw target admission before any request-dependent bootstrap; never route a clipped prefix. */
final class EarlyIngressGuard
{
    public const TARGET_BYTES = 4096;

    /** @param mixed $rawTarget Missing/non-string values are admitted; index normalizes them to '/'. */
    public static function accepts($rawTarget): bool
    {
        return !is_string($rawTarget) || strlen($rawTarget) <= self::TARGET_BYTES;
    }
}
