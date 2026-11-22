<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

/**
 * The short-lived HS256 JWT the API's password login returns. It is signed with the surface's own
 * jwt key, never with the persona's published `secret.jwt`, so a token re-signed with the leaked
 * secret is rejected like any forgery. Anything other than HS256 (including `alg: none`), a bad
 * signature, an expired token or an oversized token decodes to null. `kid` is ignored.
 */
final class JwtCodec
{
    public const MAX_BYTES = 4096;
    public const LIFETIME_S = 900;

    /** @param array<string,mixed> $claims */
    public static function encode(array $claims, string $key): string
    {
        $head = self::b64((string) json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
        $body = self::b64((string) json_encode($claims, JSON_UNESCAPED_SLASHES));

        return $head . '.' . $body . '.' . self::b64(hash_hmac('sha256', $head . '.' . $body, $key, true));
    }

    /** @return array<string,mixed>|null the claims of a valid, unexpired token */
    public static function decode(string $jwt, string $key, int $now): ?array
    {
        if ($jwt === '' || strlen($jwt) > self::MAX_BYTES || substr_count($jwt, '.') !== 2) {
            return null;
        }
        [$head, $body, $sig] = explode('.', $jwt);
        $header = self::json($head);
        $claims = self::json($body);
        $rawSig = self::unb64($sig);
        if ($header === null || $claims === null || $rawSig === null || ($header['alg'] ?? null) !== 'HS256') {
            return null;
        }
        if (!hash_equals(hash_hmac('sha256', $head . '.' . $body, $key, true), $rawSig)) {
            return null;
        }
        $exp = $claims['exp'] ?? null;
        if (!is_int($exp) || $exp <= $now) {
            return null;
        }

        return $claims;
    }

    public static function looksLikeJwt(string $s): bool
    {
        return substr_count($s, '.') === 2 && preg_match('/\A[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\z/', $s) === 1;
    }

    private static function b64(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    private static function unb64(string $s): ?string
    {
        if (preg_match('/\A[A-Za-z0-9_-]*\z/', $s) !== 1) {
            return null;
        }
        $raw = base64_decode(strtr($s, '-_', '+/'), true);

        return $raw === false ? null : $raw;
    }

    /** @return array<string,mixed>|null */
    private static function json(string $segment): ?array
    {
        $raw = self::unb64($segment);
        if ($raw === null || $raw === '') {
            return null;
        }
        $v = json_decode($raw, true, 4);

        return is_array($v) && !array_is_list($v) ? $v : null;
    }
}
