<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

/**
 * Turns a generated host's index into the tag in its name and back, so a name resolves only if this
 * deploy generated it.
 *
 * The tag is six base36 characters holding a 31-bit value: a keyed 16-bit permutation of the index
 * (a four-round Feistel network) in the high 16 bits and a keyed 15-bit MAC of the index in the low 15.
 * Decoding inverts the permutation and checks the MAC; the caller then checks the name's stem and zone
 * against the node. A one-character edit passes the MAC about once in 32,768 tries, and the stem and
 * zone checks cut that further.
 */
final class NameCodec
{
    public const INDEXES = 65536;
    private const ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyz';
    private const LIMIT = 2147483648;

    public function __construct(private string $key)
    {
    }

    public function tag(int $index): string
    {
        $v = ($this->permute($index & 0xffff) << 15) | $this->mac($index & 0xffff);
        $out = '';
        for ($i = 0; $i < 6; $i++) {
            $out = self::ALPHABET[$v % 36] . $out;
            $v = intdiv($v, 36);
        }

        return $out;
    }

    /** The index a tag encodes, or null when it is not one of ours. */
    public function index(string $tag): ?int
    {
        if (strlen($tag) !== 6 || strspn($tag, self::ALPHABET) !== 6) {
            return null;
        }
        $v = 0;
        for ($i = 0; $i < 6; $i++) {
            $v = $v * 36 + (int) strpos(self::ALPHABET, $tag[$i]);
        }
        if ($v >= self::LIMIT) {
            return null;
        }
        $index = $this->unpermute($v >> 15);

        return $this->mac($index) === ($v & 0x7fff) ? $index : null;
    }

    private function round(int $r, int $half): int
    {
        return ord(hash_hmac('sha256', 'feistel' . $r . '|' . $half, $this->key, true)[0]);
    }

    private function permute(int $x): int
    {
        $l = $x >> 8;
        $r = $x & 255;
        for ($i = 0; $i < 4; $i++) {
            [$l, $r] = [$r, $l ^ $this->round($i, $r)];
        }

        return ($l << 8) | $r;
    }

    private function unpermute(int $y): int
    {
        $l = $y >> 8;
        $r = $y & 255;
        for ($i = 3; $i >= 0; $i--) {
            [$l, $r] = [$r ^ $this->round($i, $l), $l];
        }

        return ($l << 8) | $r;
    }

    private function mac(int $index): int
    {
        $h = hash_hmac('sha256', 'mac|' . $index, $this->key, true);

        return ((ord($h[0]) << 8) | ord($h[1])) & 0x7fff;
    }
}
