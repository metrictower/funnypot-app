<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Protocol\Ssh\KeyDerivation;
use PHPUnit\Framework\TestCase;

/**
 * RFC 4253 §7.2 key derivation with the key-expansion extension (FP-0288). Pins that short keys
 * are bit-identical to the former one-shot derivation (no regression on the live aes256-ctr path)
 * and that longer-than-hashlen keys extend by the HASH(K ‖ H ‖ K1 ‖ …) chain. No published KAT
 * exists for the extension; parity with real clients lands in FP-0291's interop.
 */
final class SshKeyDerivationTest extends TestCase
{
    private string $k;
    private string $h;

    protected function setUp(): void
    {
        // $k is the shared secret already encoded as the kex hashes it (mpint); its exact bytes do
        // not matter to these structural pins, only that derive() feeds it verbatim.
        $this->k = "\x00\x00\x00\x21\x00" . random_bytes(32);
        $this->h = hash('sha256', 'exchange-hash', true);
    }

    public function test_short_key_matches_the_one_shot_formula(): void
    {
        // The pre-FP-0288 Kex.php:61 derivation, reproduced independently.
        foreach (['A', 'B', 'C', 'D', 'E', 'F'] as $letter) {
            $oneShot = hash('sha256', $this->k . $this->h . $letter . $this->h, true);
            self::assertSame(
                bin2hex(substr($oneShot, 0, 16)),
                bin2hex(KeyDerivation::derive('sha256', $this->k, $this->h, $this->h, $letter, 16)),
                "letter {$letter} iv (16)"
            );
            self::assertSame(
                bin2hex(substr($oneShot, 0, 32)),
                bin2hex(KeyDerivation::derive('sha256', $this->k, $this->h, $this->h, $letter, 32)),
                "letter {$letter} key (32)"
            );
        }
    }

    public function test_extension_chains_hash_blocks(): void
    {
        $k1 = hash('sha256', $this->k . $this->h . 'C' . $this->h, true);
        $k2 = hash('sha256', $this->k . $this->h . $k1, true);
        $k3 = hash('sha256', $this->k . $this->h . $k1 . $k2, true);

        $need64 = KeyDerivation::derive('sha256', $this->k, $this->h, $this->h, 'C', 64);
        self::assertSame(64, strlen($need64));
        self::assertSame(bin2hex($k1), bin2hex(substr($need64, 0, 32)), 'first block is K1');
        self::assertSame(bin2hex($k2), bin2hex(substr($need64, 32, 32)), 'second block is HASH(K‖H‖K1)');

        $need70 = KeyDerivation::derive('sha256', $this->k, $this->h, $this->h, 'C', 70);
        self::assertSame(70, strlen($need70));
        self::assertSame(bin2hex(substr($k3, 0, 6)), bin2hex(substr($need70, 64, 6)), 'third block is HASH(K‖H‖K1‖K2)');
    }

    public function test_zero_need_is_empty(): void
    {
        self::assertSame('', KeyDerivation::derive('sha256', $this->k, $this->h, $this->h, 'A', 0));
    }

    public function test_sha512_single_block_for_64_bytes(): void
    {
        $expected = hash('sha512', $this->k . $this->h . 'C' . $this->h, true);
        self::assertSame(
            bin2hex($expected),
            bin2hex(KeyDerivation::derive('sha512', $this->k, $this->h, $this->h, 'C', 64)),
            'a 64-byte need under sha512 is one hash block, no extension'
        );
    }

    public function test_derive_all_maps_letters_to_directions(): void
    {
        $all = KeyDerivation::deriveAll('sha256', $this->k, $this->h, $this->h, 16, 32, 32);
        self::assertSame(
            ['ivC2S', 'ivS2C', 'keyC2S', 'keyS2C', 'macC2S', 'macS2C'],
            array_keys($all)
        );
        // RFC 4253 §7.2 letters A–F map to iv/key/mac C2S/S2C in order.
        foreach (['ivC2S' => 'A', 'ivS2C' => 'B', 'keyC2S' => 'C', 'keyS2C' => 'D', 'macC2S' => 'E', 'macS2C' => 'F'] as $field => $letter) {
            $need = $field[0] === 'i' ? 16 : 32;
            self::assertSame(
                bin2hex(KeyDerivation::derive('sha256', $this->k, $this->h, $this->h, $letter, $need)),
                bin2hex($all[$field]),
                "{$field} <- letter {$letter}"
            );
        }
    }
}
