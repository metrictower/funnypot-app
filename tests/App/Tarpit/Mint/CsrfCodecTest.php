<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Mint;

use Funnypot\App\Tarpit\Mint\CsrfCodec;
use PHPUnit\Framework\TestCase;

final class CsrfCodecTest extends TestCase
{
    private const NOW = 1763800000;

    public function test_round_trip_returns_the_issue_time(): void
    {
        $c = new CsrfCodec(str_repeat('c', 32));
        $t = $c->issue('sid-0001', 'token_create', 4, self::NOW);
        self::assertSame(36, strlen($t));
        self::assertSame(self::NOW, $c->verify($t, 'sid-0001', 'token_create', 4, self::NOW + 100));
    }

    public function test_bound_to_session_form_and_epoch(): void
    {
        $c = new CsrfCodec(str_repeat('c', 32));
        $t = $c->issue('sid-0001', 'token_create', 4, self::NOW);
        self::assertNull($c->verify($t, 'sid-0002', 'token_create', 4, self::NOW), 'cross-session');
        self::assertNull($c->verify($t, 'sid-0001', 'app_create', 4, self::NOW), 'cross-form');
        self::assertNull($c->verify($t, 'sid-0001', 'token_create', 5, self::NOW), 'old epoch');
        self::assertNull((new CsrfCodec(str_repeat('d', 32)))->verify($t, 'sid-0001', 'token_create', 4, self::NOW));
    }

    public function test_age_limit_and_malformed_input(): void
    {
        $c = new CsrfCodec(str_repeat('c', 32));
        $t = $c->issue('s', 'f', 0, self::NOW);
        self::assertSame(self::NOW, $c->verify($t, 's', 'f', 0, self::NOW + CsrfCodec::MAX_AGE_S));
        self::assertNull($c->verify($t, 's', 'f', 0, self::NOW + CsrfCodec::MAX_AGE_S + 1), 'over an hour');
        self::assertNull($c->verify($t, 's', 'f', 0, self::NOW - 10), 'issued in the future');
        foreach ([null, '', str_repeat('A', 36), str_repeat('A', 37), str_repeat('!', 36), str_repeat('A', 9000)] as $bad) {
            self::assertNull($c->verify($bad, 's', 'f', 0, self::NOW));
        }
        $tampered = $t;
        $tampered[10] = $tampered[10] === 'A' ? 'B' : 'A';
        self::assertNull($c->verify($tampered, 's', 'f', 0, self::NOW));
    }

    public function test_a_token_we_issued_is_recognised_however_stale_and_a_guess_never_is(): void
    {
        $c = new CsrfCodec(str_repeat('c', 32));
        $t = $c->issue('sid-0001', 'token_delete', 4, self::NOW);
        self::assertTrue($c->issuedByUs($t));
        self::assertNull($c->verify($t, 'sid-0002', 'token_delete', 4, self::NOW), 'stale for another session');
        self::assertNull($c->verify($t, 'sid-0001', 'token_delete', 5, self::NOW), 'stale after an epoch bump');
        self::assertNull($c->verify($t, 'sid-0001', 'token_delete', 4, self::NOW + 4000), 'expired');
        self::assertTrue($c->issuedByUs($t), 'still recognisably ours');
        self::assertFalse((new CsrfCodec(str_repeat('d', 32)))->issuedByUs($t), 'another key never issued it');
        foreach ([null, '', str_repeat('A', 36), 'x', str_repeat('A', 9000)] as $guess) {
            self::assertFalse($c->issuedByUs($guess));
        }
        $raw = (string) base64_decode(strtr($t, '-_', '+/') . '=');
        $forged = rtrim(strtr(base64_encode(substr($raw, 0, 20) . str_repeat("\0", 7)), '+/', '-_'), '=');
        self::assertFalse($c->issuedByUs($forged), 'a wrong origin MAC');
    }

    public function test_tokens_issued_in_the_same_second_share_no_head_and_no_tail(): void
    {
        $c = new CsrfCodec(str_repeat('c', 32));
        $tokens = [
            $c->issue('sid-0001', 'app_secret', 0, self::NOW),
            $c->issue('sid-0001', 'app_delete', 0, self::NOW),
            $c->issue('sid-0002', 'profile', 3, self::NOW),
            $c->issue('sid-0001', 'app_secret', 1, self::NOW),
        ];
        foreach ($tokens as $i => $a) {
            self::assertTrue($c->issuedByUs($a));
            foreach ($tokens as $j => $b) {
                if ($i < $j) {
                    self::assertNotSame(substr($a, -9), substr($b, -9), "tokens {$i} and {$j} share their tail");
                    self::assertNotSame(substr($a, 0, 6), substr($b, 0, 6), "tokens {$i} and {$j} share their head: the clock spells it");
                    self::assertNotSame(substr($a, 21, 6), substr($b, 21, 6), "tokens {$i} and {$j} share the masked time");
                }
            }
        }
        self::assertSame(self::NOW, $c->verify($tokens[0], 'sid-0001', 'app_secret', 0, self::NOW), 'sanity: the same issue second');
        // One second earlier changes the whole token, head included, so a re-roll is never stuck on the clock.
        $earlier = $c->issue('sid-0001', 'app_secret', 0, self::NOW - 1);
        self::assertNotSame(substr($tokens[0], 0, 6), substr($earlier, 0, 6));
        self::assertSame(self::NOW - 1, $c->verify($earlier, 'sid-0001', 'app_secret', 0, self::NOW));
        // Changing the middle of a token of ours no longer leaves it recognisably ours.
        $raw = (string) base64_decode(strtr($tokens[0], '-_', '+/') . '=');
        $raw[10] = chr(ord($raw[10]) ^ 1);
        self::assertFalse($c->issuedByUs(rtrim(strtr(base64_encode($raw), '+/', '-_'), '=')));
    }
}
