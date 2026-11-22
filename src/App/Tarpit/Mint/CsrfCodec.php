<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

/**
 * The `csrf_token` form field: base64url(issuedAt u32 ‖ HMAC(csrf, sid ‖ formId ‖ epoch ‖ issuedAt)[0..16]).
 *
 * A token is bound to one session, one form and the account's current CSRF epoch, and lives at most
 * an hour. Bumping the epoch invalidates every form the account has open, which is how a "stale form"
 * stays true on the next submit.
 */
final class CsrfCodec
{
    public const FIELD = 'csrf_token';
    public const MAX_AGE_S = 3600;

    public function __construct(private string $key)
    {
    }

    public function issue(string $sid, string $formId, int $epoch, int $issuedAt): string
    {
        $t = pack('N', $issuedAt);

        return rtrim(strtr(base64_encode($t . $this->mac($sid, $formId, $epoch, $t)), '+/', '-_'), '=');
    }

    /** @return int|null the token's issue time when it is valid for this session, form and epoch */
    public function verify(?string $token, string $sid, string $formId, int $epoch, int $now): ?int
    {
        if ($token === null || strlen($token) !== 27 || preg_match('/\A[A-Za-z0-9_-]{27}\z/', $token) !== 1) {
            return null;
        }
        $raw = base64_decode(strtr($token, '-_', '+/'), true);
        if ($raw === false || strlen($raw) !== 20) {
            return null;
        }
        $t = substr($raw, 0, 4);
        if (!hash_equals($this->mac($sid, $formId, $epoch, $t), substr($raw, 4))) {
            return null;
        }
        $issuedAt = (int) unpack('N', $t)[1];
        if ($issuedAt > $now + 5 || $now - $issuedAt > self::MAX_AGE_S) {
            return null;
        }

        return $issuedAt;
    }

    private function mac(string $sid, string $formId, int $epoch, string $t): string
    {
        return substr(hash_hmac('sha256', "csrf\0" . $sid . "\0" . $formId . "\0" . $epoch . "\0" . $t, $this->key, true), 0, 16);
    }
}
