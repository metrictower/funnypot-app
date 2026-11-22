<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

/**
 * The `csrf_token` form field: base64url(issuedAt u32 ‖ HMAC(csrf, sid ‖ formId ‖ epoch ‖ issuedAt)[0..16] ‖
 * HMAC(csrf, issuedAt)[0..7]), 36 characters.
 *
 * A token is valid for one session, one form and the account's current CSRF epoch, for at most an hour.
 * Bumping the epoch invalidates every form the account has open, which is how a "stale form" stays true
 * on the next submit. The short second MAC proves only that this surface issued the token, so a stale
 * or used form of ours can be told apart from a guess.
 */
final class CsrfCodec
{
    public const FIELD = 'csrf_token';
    public const MAX_AGE_S = 3600;

    private const CHARS = 36;
    private const RAW_BYTES = 27;

    public function __construct(private string $key)
    {
    }

    public function issue(string $sid, string $formId, int $epoch, int $issuedAt): string
    {
        $t = pack('N', $issuedAt);

        return rtrim(strtr(base64_encode($t . $this->mac($sid, $formId, $epoch, $t) . $this->origin($t)), '+/', '-_'), '=');
    }

    /** @return int|null the token's issue time when it is valid for this session, form and epoch */
    public function verify(?string $token, string $sid, string $formId, int $epoch, int $now): ?int
    {
        $raw = self::raw($token);
        if ($raw === null) {
            return null;
        }
        $t = substr($raw, 0, 4);
        if (!hash_equals($this->mac($sid, $formId, $epoch, $t), substr($raw, 4, 16))) {
            return null;
        }
        $issuedAt = (int) unpack('N', $t)[1];
        if ($issuedAt > $now + 5 || $now - $issuedAt > self::MAX_AGE_S) {
            return null;
        }

        return $issuedAt;
    }

    /** Whether this surface issued the token, however stale, expired or used it is now. */
    public function issuedByUs(?string $token): bool
    {
        $raw = self::raw($token);

        return $raw !== null && hash_equals($this->origin(substr($raw, 0, 4)), substr($raw, 20, 7));
    }

    private static function raw(?string $token): ?string
    {
        if ($token === null || strlen($token) !== self::CHARS || preg_match('/\A[A-Za-z0-9_-]{36}\z/', $token) !== 1) {
            return null;
        }
        $raw = base64_decode(strtr($token, '-_', '+/'), true);

        return $raw === false || strlen($raw) !== self::RAW_BYTES ? null : $raw;
    }

    private function mac(string $sid, string $formId, int $epoch, string $t): string
    {
        return substr(hash_hmac('sha256', "csrf\0" . $sid . "\0" . $formId . "\0" . $epoch . "\0" . $t, $this->key, true), 0, 16);
    }

    private function origin(string $t): string
    {
        return substr(hash_hmac('sha256', "csrf-origin\0" . $t, $this->key, true), 0, 7);
    }
}
