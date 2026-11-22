<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

/**
 * The `session` cookie: base64url(kref16 ‖ acct u8 ‖ sid8 ‖ issuedAt u32 ‖ mac16), 60 characters.
 *
 * It carries the source reference, so a session keeps working from another IP. The codec checks the
 * MAC and the absolute lifetime only; whether the sid is still live (not revoked, not idle past its
 * window) is a fact of state, checked by the caller.
 */
final class SessionCodec
{
    public const COOKIE = 'session';
    public const ABSOLUTE_S = 28800;
    public const IDLE_S = 7200;

    private const RAW_BYTES = 45;

    public function __construct(private string $key)
    {
    }

    public function issue(string $kref, int $acct, string $sid, int $issuedAt): string
    {
        $head = $kref . chr($acct & 0xff) . $sid . pack('N', $issuedAt);

        return rtrim(strtr(base64_encode($head . $this->mac($head)), '+/', '-_'), '=');
    }

    /** @return array{kref:string,acct:int,sid:string,issuedAt:int}|null */
    public function parse(string $cookie, int $now): ?array
    {
        if (strlen($cookie) !== 60 || preg_match('/\A[A-Za-z0-9_-]{60}\z/', $cookie) !== 1) {
            return null;
        }
        $raw = base64_decode(strtr($cookie, '-_', '+/'), true);
        if ($raw === false || strlen($raw) !== self::RAW_BYTES) {
            return null;
        }
        $head = substr($raw, 0, 29);
        if (!hash_equals($this->mac($head), substr($raw, 29))) {
            return null;
        }
        $issuedAt = (int) unpack('N', substr($head, 25, 4))[1];
        if ($issuedAt > $now + 60 || $now - $issuedAt > self::ABSOLUTE_S) {
            return null;
        }

        return ['kref' => substr($head, 0, 16), 'acct' => ord($head[16]), 'sid' => substr($head, 17, 8), 'issuedAt' => $issuedAt];
    }

    private function mac(string $head): string
    {
        return substr(hash_hmac('sha256', "session\0" . $head, $this->key, true), 0, 16);
    }
}
