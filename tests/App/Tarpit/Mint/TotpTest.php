<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Mint;

use Funnypot\App\Tarpit\Mint\Totp;
use PHPUnit\Framework\TestCase;

final class TotpTest extends TestCase
{
    /** RFC 6238 Appendix B, SHA-1 rows: the 20-byte ASCII secret "12345678901234567890". */
    public function test_rfc6238_sha1_vectors(): void
    {
        $secret = '12345678901234567890';
        $vectors = [59 => '94287082', 1111111109 => '07081804', 1111111111 => '14050471', 1234567890 => '89005924', 2000000000 => '69279037', 20000000000 => '65353130'];
        foreach ($vectors as $t => $code) {
            self::assertSame($code, Totp::code($secret, Totp::step($t), 8), "T={$t}");
            self::assertSame(substr($code, 2), Totp::code($secret, Totp::step($t)), "6-digit truncation at T={$t}");
        }
    }

    public function test_window_is_plus_minus_one_step_only(): void
    {
        $secret = random_bytes(20);
        $now = 1763800005;
        $t = Totp::step($now);
        foreach ([-1, 0, 1] as $d) {
            self::assertSame($t + $d, Totp::verify($secret, Totp::code($secret, $t + $d), $now, 0));
        }
        foreach ([-2, 2] as $d) {
            $code = Totp::code($secret, $t + $d);
            if (!in_array($code, [Totp::code($secret, $t - 1), Totp::code($secret, $t), Totp::code($secret, $t + 1)], true)) {
                self::assertNull(Totp::verify($secret, $code, $now, 0), "offset {$d}");
            }
        }
    }

    public function test_an_accepted_step_cannot_be_replayed(): void
    {
        $secret = random_bytes(20);
        $now = 1763800005;
        $code = Totp::code($secret, Totp::step($now));
        $accepted = Totp::verify($secret, $code, $now, 0);
        self::assertSame(Totp::step($now), $accepted);
        self::assertNull(Totp::verify($secret, $code, $now, (int) $accepted), 'the same step again');
        self::assertNull(Totp::verify($secret, Totp::code($secret, Totp::step($now) - 1), $now, (int) $accepted), 'an earlier step');
        self::assertSame(Totp::step($now) + 1, Totp::verify($secret, Totp::code($secret, Totp::step($now) + 1), $now, (int) $accepted), 'the next step still works');
    }

    public function test_malformed_codes_and_base32(): void
    {
        foreach (['', '12345', '1234567', 'abcdef', "12345\n", '١٢٣٤٥٦'] as $bad) {
            self::assertNull(Totp::verify('s', $bad, 1763800005, 0));
        }
        self::assertSame('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', Totp::base32('12345678901234567890'));
        self::assertSame(32, strlen(Totp::base32(random_bytes(20))));
    }
}
