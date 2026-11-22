<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Mint;

use Funnypot\App\Tarpit\Mint\SessionCodec;
use PHPUnit\Framework\TestCase;

final class SessionCodecTest extends TestCase
{
    private const NOW = 1763800000;

    public function test_round_trip(): void
    {
        $c = new SessionCodec(str_repeat('k', 32));
        $cookie = $c->issue(str_repeat("\x07", 16), 3, 'sid-8byt', self::NOW);
        self::assertSame(60, strlen($cookie));
        $p = $c->parse($cookie, self::NOW + 10);
        self::assertSame(['kref' => str_repeat("\x07", 16), 'acct' => 3, 'sid' => 'sid-8byt', 'issuedAt' => self::NOW], $p);
    }

    public function test_tamper_and_wrong_key_are_invalid(): void
    {
        $c = new SessionCodec(str_repeat('k', 32));
        $cookie = $c->issue(str_repeat("\x07", 16), 3, 'sid-8byt', self::NOW);
        for ($i = 0; $i < 60; $i++) {
            $t = $cookie;
            $t[$i] = $t[$i] === 'A' ? 'B' : 'A';
            self::assertNull($c->parse($t, self::NOW), "char {$i}");
        }
        self::assertNull((new SessionCodec(str_repeat('j', 32)))->parse($cookie, self::NOW));
        foreach (['', 'x', str_repeat('A', 59), str_repeat('A', 61), str_repeat('*', 60), str_repeat('A', 4096)] as $bad) {
            self::assertNull($c->parse($bad, self::NOW));
        }
    }

    public function test_absolute_expiry_and_future_issue(): void
    {
        $c = new SessionCodec(str_repeat('k', 32));
        $cookie = $c->issue(str_repeat("\x07", 16), 0, 'sid-8byt', self::NOW);
        self::assertNotNull($c->parse($cookie, self::NOW + SessionCodec::ABSOLUTE_S));
        self::assertNull($c->parse($cookie, self::NOW + SessionCodec::ABSOLUTE_S + 1));
        self::assertNull($c->parse($cookie, self::NOW - 61), 'issued in the future');
    }
}
