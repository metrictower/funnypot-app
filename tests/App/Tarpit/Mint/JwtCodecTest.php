<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Mint;

use Funnypot\App\Tarpit\Mint\JwtCodec;
use PHPUnit\Framework\TestCase;

final class JwtCodecTest extends TestCase
{
    private const KEY = 'jwt-key-0123456789abcdef0123456789';
    private const NOW = 1763800000;

    private static function b64(string $s): string
    {
        return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
    }

    public function test_round_trip_is_a_three_segment_hs256_token(): void
    {
        $t = JwtCodec::encode(['sub' => 'u', 'exp' => self::NOW + 900, 'scope' => 'read:user'], self::KEY);
        self::assertSame(2, substr_count($t, '.'));
        self::assertTrue(JwtCodec::looksLikeJwt($t));
        $claims = JwtCodec::decode($t, self::KEY, self::NOW);
        self::assertSame('u', $claims['sub'] ?? null);
        self::assertSame('{"alg":"HS256","typ":"JWT"}', base64_decode(strtr(explode('.', $t)[0], '-_', '+/')));
    }

    public function test_alg_none_and_other_algs_are_rejected(): void
    {
        $body = self::b64((string) json_encode(['sub' => 'u', 'exp' => self::NOW + 900]));
        self::assertNull(JwtCodec::decode(self::b64('{"alg":"none","typ":"JWT"}') . '.' . $body . '.', self::KEY, self::NOW));
        self::assertNull(JwtCodec::decode(self::b64('{"alg":"none"}') . '.' . $body . '.', self::KEY, self::NOW));
        $hs512 = self::b64('{"alg":"HS512","typ":"JWT"}');
        self::assertNull(JwtCodec::decode($hs512 . '.' . $body . '.' . self::b64(hash_hmac('sha512', $hs512 . '.' . $body, self::KEY, true)), self::KEY, self::NOW));
    }

    public function test_a_token_signed_with_another_key_is_invalid(): void
    {
        $leaked = 'the-persona-published-jwt-secret';
        $forged = JwtCodec::encode(['sub' => 'admin', 'exp' => self::NOW + 900, 'role' => 'owner'], $leaked);
        self::assertNull(JwtCodec::decode($forged, self::KEY, self::NOW));
        self::assertNotNull(JwtCodec::decode($forged, $leaked, self::NOW), 'sanity: it is a well-formed token');
    }

    public function test_expired_and_missing_exp_are_invalid(): void
    {
        self::assertNull(JwtCodec::decode(JwtCodec::encode(['sub' => 'u', 'exp' => self::NOW], self::KEY), self::KEY, self::NOW));
        self::assertNull(JwtCodec::decode(JwtCodec::encode(['sub' => 'u'], self::KEY), self::KEY, self::NOW));
        self::assertNull(JwtCodec::decode(JwtCodec::encode(['sub' => 'u', 'exp' => '9999999999'], self::KEY), self::KEY, self::NOW));
    }

    public function test_oversized_tokens_are_rejected_before_decoding(): void
    {
        $big = JwtCodec::encode(['sub' => 'u', 'exp' => self::NOW + 900, 'pad' => str_repeat('a', 4000)], self::KEY);
        self::assertGreaterThan(JwtCodec::MAX_BYTES, strlen($big));
        self::assertNull(JwtCodec::decode($big, self::KEY, self::NOW));
        self::assertNull(JwtCodec::decode(str_repeat('a.', 3000), self::KEY, self::NOW));
    }

    public function test_kid_is_ignored_and_malformed_segments_fail_quietly(): void
    {
        $head = self::b64('{"alg":"HS256","typ":"JWT","kid":"../../../../dev/null"}');
        $body = self::b64((string) json_encode(['sub' => 'u', 'exp' => self::NOW + 900]));
        $sig = self::b64(hash_hmac('sha256', $head . '.' . $body, self::KEY, true));
        self::assertSame('u', JwtCodec::decode($head . '.' . $body . '.' . $sig, self::KEY, self::NOW)['sub'] ?? null);
        set_error_handler(static function (int $no, string $msg): bool {
            if ((error_reporting() & $no) === 0) {
                return true;
            }
            throw new \ErrorException($msg, 0, $no);
        });
        try {
            foreach (['', '.', '..', 'a.b.c', '!!.@@.##', self::b64('[[[[[[1]]]]]]') . '.' . $body . '.' . $sig, self::b64('{"alg":"HS256"}') . '.' . self::b64('"str"') . '.x'] as $bad) {
                self::assertNull(JwtCodec::decode($bad, self::KEY, self::NOW), $bad);
            }
        } finally {
            restore_error_handler();
        }
    }
}
