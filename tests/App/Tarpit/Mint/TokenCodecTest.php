<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Mint;

use Funnypot\App\Tarpit\InertSecret;
use Funnypot\App\Tarpit\Mint\TokenCodec;
use Funnypot\Core\Support\PersonaIdentity;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class TokenCodecTest extends TestCase
{
    private function codec(string $prefix = 'pal'): TokenCodec
    {
        return new TokenCodec(str_repeat("\x11", 32), $prefix);
    }

    public function test_shape_and_round_trip(): void
    {
        $c = $this->codec();
        $k8 = "\x00\x01\x02\x03\xfd\xfe\xff\x80";
        foreach (TokenCodec::KINDS as $kind) {
            $t = $c->encode($kind, $k8, 5, 200, 'bind-a');
            self::assertMatchesRegularExpression(TokenCodec::SHAPE, $t);
            self::assertStringStartsWith('pal_' . $kind . '_', $t);
            $d = $c->decode($t);
            self::assertNotNull($d);
            self::assertSame($kind, $d['kind']);
            self::assertSame($k8, $d['k8']);
            self::assertSame(5, $d['acct']);
            self::assertSame(200, $d['serial']);
            self::assertTrue($c->verify($d, 'bind-a'));
            self::assertFalse($c->verify($d, 'bind-b'), 'a different binding never verifies');
        }
    }

    public function test_extreme_bodies_round_trip(): void
    {
        $c = $this->codec();
        foreach ([str_repeat("\x00", 8), str_repeat("\xff", 8)] as $k8) {
            foreach ([[0, 0], [255, 255]] as [$a, $s]) {
                $t = $c->encode('pat', $k8, $a, $s, 'x');
                $d = $c->decode($t);
                self::assertNotNull($d, $t);
                self::assertSame($k8, $d['k8']);
                self::assertTrue($c->verify($d, 'x'));
            }
        }
    }

    public function test_tamper_and_kind_swap_are_invalid(): void
    {
        $c = $this->codec();
        $t = $c->encode('pat', '12345678', 1, 2, 'b');
        $body = substr($t, 8);
        for ($i = 0; $i < 31; $i++) {
            $flipped = $body;
            $flipped[$i] = $flipped[$i] === 'a' ? 'b' : 'a';
            $d = $c->decode('pal_pat_' . $flipped);
            self::assertTrue($d === null || !$c->verify($d, 'b'), "flipping char {$i} must not verify");
        }
        $swapped = $c->decode('pal_oat_' . $body);
        self::assertNotNull($swapped);
        self::assertFalse($c->verify($swapped, 'b'), 'a pat body relabelled oat never verifies');
        self::assertNull($c->decode('xyz_pat_' . $body), 'another prefix is not ours');
        self::assertNull($c->decode($t . 'A'));
        self::assertNull($c->decode(substr($t, 0, -1)));
        self::assertNull($c->decode('pal_pat_' . str_repeat('z', 31)), 'a body over 23 bytes is rejected');
        self::assertNull($c->decode(str_repeat('a', 5000)));
    }

    public function test_no_vendor_prefix_for_any_persona(): void
    {
        for ($seed = 0; $seed < 400; $seed++) {
            $slug = (string) PersonaIdentity::fromSeed($seed)->field('company.slug');
            $p = TokenCodec::prefixFor($slug);
            self::assertMatchesRegularExpression('/\A[a-z]{2,4}\z/', $p);
            self::assertNotContains($p, TokenCodec::VENDOR_PREFIXES);
            $t = (new TokenCodec('k', $p))->encode('pat', '12345678', 0, 0, '');
            foreach (['ghp_', 'gho_', 'github_pat_', 'glpat-', 'xox', 'sk_', 'sk-'] as $vendor) {
                self::assertStringStartsNotWith($vendor, $t);
            }
        }
        $this->expectException(InvalidArgumentException::class);
        new TokenCodec('k', 'ghp');
    }

    public function test_tokens_are_clean_over_many_serials_and_seeds(): void
    {
        for ($seed = 1; $seed <= 8; $seed++) {
            $c = new TokenCodec(hash('sha256', 'seed' . $seed, true), TokenCodec::prefixFor((string) PersonaIdentity::fromSeed($seed)->field('company.slug')));
            $dirty = 0;
            for ($n = 0; $n < 1000; $n++) {
                $t = $c->encode('pat', substr(hash('sha256', (string) $n, true), 0, 8), $n % 7, $n % 256, 'n' . $n);
                if (!InertSecret::isClean('"' . $t . '"')) {
                    $dirty++;
                }
            }
            // A raw draw can be dirty only by a one-in-a-million tail; the minting path re-derives such a
            // draw under the next variant, so this pins that the raw space is overwhelmingly clean.
            self::assertLessThanOrEqual(1, $dirty, "seed {$seed}");
        }
    }
}
