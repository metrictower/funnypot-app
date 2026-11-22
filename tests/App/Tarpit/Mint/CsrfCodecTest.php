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
        self::assertSame(27, strlen($t));
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
        foreach ([null, '', str_repeat('A', 27), str_repeat('A', 28), str_repeat('!', 27), str_repeat('A', 9000)] as $bad) {
            self::assertNull($c->verify($bad, 's', 'f', 0, self::NOW));
        }
        $tampered = $t;
        $tampered[10] = $tampered[10] === 'A' ? 'B' : 'A';
        self::assertNull($c->verify($tampered, 's', 'f', 0, self::NOW));
    }
}
