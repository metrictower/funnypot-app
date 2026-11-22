<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

/**
 * RFC 6238 time-based one-time codes (HMAC-SHA1, 30-second steps), so an agent can compute a real
 * code from the enrolment secret. Verification accepts the current step and one step either side,
 * and never a step at or before the last one accepted, so a code cannot be replayed.
 */
final class Totp
{
    public const STEP_S = 30;

    private const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public static function step(int $now): int
    {
        return intdiv(max(0, $now), self::STEP_S);
    }

    public static function code(string $secret, int $step, int $digits = 6): string
    {
        $hmac = hash_hmac('sha1', pack('J', $step), $secret, true);
        $off = ord($hmac[19]) & 0x0f;
        $bin = ((ord($hmac[$off]) & 0x7f) << 24) | (ord($hmac[$off + 1]) << 16) | (ord($hmac[$off + 2]) << 8) | ord($hmac[$off + 3]);

        return str_pad((string) ($bin % (10 ** $digits)), $digits, '0', STR_PAD_LEFT);
    }

    /** @return int|null the accepted step, or null for a wrong, expired or replayed code */
    public static function verify(string $secret, string $code, int $now, int $lastStep): ?int
    {
        if (preg_match('/\A[0-9]{6}\z/', $code) !== 1) {
            return null;
        }
        $t = self::step($now);
        foreach ([$t - 1, $t, $t + 1] as $s) {
            if ($s > $lastStep && hash_equals(self::code($secret, $s), $code)) {
                return $s;
            }
        }

        return null;
    }

    public static function base32(string $raw): string
    {
        $bits = '';
        $len = strlen($raw);
        for ($i = 0; $i < $len; $i++) {
            $bits .= str_pad(decbin(ord($raw[$i])), 8, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 5) as $chunk) {
            $out .= self::BASE32[bindec(str_pad($chunk, 5, '0'))];
        }

        return $out;
    }
}
