<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh\Cipher;

/**
 * UMAC (RFC 4418), the message authentication code behind OpenSSH's umac-64/umac-128(@openssh.com)
 * MACs. A faithful pure-PHP port of OpenSSH's umac.c (Ted Krovetz's reference implementation): the
 * AES-128 KDF, the NH universal hash over 1024-byte L1 blocks, the ramped poly64 layer, the
 * inner-product (ip) hash, and the AES pad-derivation function (PDF) whose output is XORed into the
 * final tag. Verified against the RFC 4418 test vectors for UMAC-32/64/96 (see SshUmacTest); UMAC-128
 * is the same algorithm with a fourth NH/poly/ip stream and its first 12 bytes equal UMAC-96 by
 * construction, which the vectors also pin.
 *
 * 64-bit arithmetic is done in explicit 32-bit limbs (no gmp/bcmath): PHP promotes an overflowing
 * int to float, so nothing may rely on wraparound. NH data words are little-endian, NH key words are
 * big-endian (RFC 4418 §5 / umac.c endian_convert), poly/ip keys big-endian, tag words big-endian.
 *
 * The OpenSSH SSH framing (mac.c mac_compute) differs from HMAC: the packet sequence number goes in
 * the 8-byte UMAC nonce, and the authenticated data carries NO seqno prefix — {@see CtrUmac} builds
 * the nonce and passes the same bytes an HMAC would cover (minus the seq).
 */
final class Umac
{
    private const P36 = 0x0000000FFFFFFFFB; // 2^36 - 5
    private const M36 = 0xFFFFFFFFF;         // low 36 bits

    private string $pdfKey;      // 16-byte AES key for the PDF
    /** @var int[] NH key as big-endian 32-bit words */
    private array $nhKey;
    /** @var array<int,array{0:int,1:int}> poly keys per stream as [hi,lo], masked to the special domain */
    private array $polyKey;
    /** @var int[] inner-product keys (STREAMS*4), each reduced mod p36 */
    private array $ipKeys;
    /** @var int[] inner-product translation words per stream (big-endian uint32) */
    private array $ipTrans;
    private int $streams;
    private int $taglen;

    /** @param string $key 16-byte UMAC key; $taglen one of 4, 8, 12, 16 (OpenSSH uses 8 and 16). */
    public function __construct(string $key, int $taglen)
    {
        if (strlen($key) !== 16 || !in_array($taglen, [4, 8, 12, 16], true)) {
            throw new \InvalidArgumentException('ssh: bad UMAC parameters');
        }
        $this->taglen = $taglen;
        $this->streams = intdiv($taglen, 4);
        $s = $this->streams;

        $this->pdfKey = self::kdf($key, 0, 16);

        $nhBytes = self::kdf($key, 1, 1024 + 16 * ($s - 1));
        $this->nhKey = array_values(unpack('N*', $nhBytes));

        $bufLen = (8 * $s + 4) * 8;
        $buf2 = self::kdf($key, 2, $bufLen);
        $this->polyKey = [];
        for ($i = 0; $i < $s; $i++) {
            $chunk = substr($buf2, 24 * $i, 8);
            $hi = unpack('N', substr($chunk, 0, 4))[1] & 0x01ffffff;
            $lo = unpack('N', substr($chunk, 4, 4))[1] & 0x01ffffff;
            $this->polyKey[$i] = [$hi, $lo];
        }

        $buf3 = self::kdf($key, 3, $bufLen);
        $this->ipKeys = [];
        for ($i = 0; $i < $s; $i++) {
            for ($j = 0; $j < 4; $j++) {
                $off = (8 * $i + 4) * 8 + $j * 8;
                $hi = unpack('N', substr($buf3, $off, 4))[1];
                $lo = unpack('N', substr($buf3, $off + 4, 4))[1];
                $this->ipKeys[$i * 4 + $j] = self::modP36($hi, $lo);
            }
        }

        $this->ipTrans = array_values(unpack('N*', self::kdf($key, 4, $s * 4)));
    }

    /**
     * The UMAC tag ($taglen bytes) of $msg under the 8-byte $nonce.
     */
    public function compute(string $nonce, string $msg): string
    {
        $s = $this->streams;
        $len = strlen($msg);
        $res = '';

        if ($len <= 1024) {
            $nhLen = $len === 0 ? 32 : (($len + 31) & ~31);
            $padded = $msg . str_repeat("\x00", $nhLen - $len);
            $d = array_values(unpack('V*', $padded));
            $nh = $this->nh($d, $nhLen >> 2, $len);
            for ($i = 0; $i < $s; $i++) {
                $res .= pack('N', ($this->ipWord($i, $nh[$i]) ^ $this->ipTrans[$i]) & 0xffffffff);
            }
        } else {
            $accum = [];
            for ($i = 0; $i < $s; $i++) {
                $accum[$i] = [0, 1]; // poly prepends a non-zero word
            }
            $off = 0;
            do {
                $d = array_values(unpack('V*', substr($msg, $off, 1024)));
                $this->polyHash($accum, $this->nh($d, 256, 1024));
                $off += 1024;
                $rem = $len - $off;
            } while ($rem >= 1024);
            $rem = $len - $off;
            if ($rem > 0) {
                $nhLen = ($rem + 31) & ~31;
                $d = array_values(unpack('V*', substr($msg, $off) . str_repeat("\x00", $nhLen - $rem)));
                $this->polyHash($accum, $this->nh($d, $nhLen >> 2, $rem));
            }
            for ($i = 0; $i < $s; $i++) {
                $a = $accum[$i];
                if (self::cmp($a, [0xffffffff, 0xffffffc5]) >= 0) { // >= p64
                    $a = self::sub($a, [0xffffffff, 0xffffffc5]);
                }
                $res .= pack('N', ($this->ipWord($i, $a) ^ $this->ipTrans[$i]) & 0xffffffff);
            }
        }

        return $this->pdfXor($nonce, $res);
    }

    // ---- NH ----

    /**
     * NH over one padded L1 block. $d is the block's little-endian 32-bit words, $nwords their count
     * (a multiple of 8), $unpaddedLen the block's real byte length (folded in as the 8·len term).
     *
     * @param int[] $d
     * @return array<int,array{0:int,1:int}> per-stream 64-bit accumulator [hi,lo]
     */
    private function nh(array $d, int $nwords, int $unpaddedLen): array
    {
        $s = $this->streams;
        $nbits = $unpaddedLen << 3;
        $h = [];
        for ($i = 0; $i < $s; $i++) {
            $h[$i] = [0, $nbits];
        }
        $k = $this->nhKey;
        for ($base = 0; $base < $nwords; $base += 8) {
            for ($st = 0; $st < $s; $st++) {
                $ko = $base + $st * 4;
                for ($m = 0; $m < 4; $m++) {
                    $t1 = ($k[$ko + $m] + $d[$base + $m]) & 0xffffffff;
                    $t2 = ($k[$ko + $m + 4] + $d[$base + $m + 4]) & 0xffffffff;
                    $h[$st] = self::add($h[$st], self::mul($t1, $t2));
                }
            }
        }

        return $h;
    }

    // ---- poly64 layer ----

    /**
     * @param array<int,array{0:int,1:int}> $accum
     * @param array<int,array{0:int,1:int}> $nhResults
     */
    private function polyHash(array &$accum, array $nhResults): void
    {
        for ($i = 0; $i < $this->streams; $i++) {
            $data = $nhResults[$i];
            if ($data[0] === 0xffffffff) {
                // Ramp fix: a word not in Z_p64 is split into two poly steps (umac.c poly_hash).
                $accum[$i] = self::poly64($accum[$i], $this->polyKey[$i], [0xffffffff, 0xffffffc4]); // p64-1
                $accum[$i] = self::poly64($accum[$i], $this->polyKey[$i], self::sub($data, [0, 59]));
            } else {
                $accum[$i] = self::poly64($accum[$i], $this->polyKey[$i], $data);
            }
        }
    }

    /**
     * poly64 Horner step modulo p64 = 2^64-59 (umac.c). $key limbs are each < 2^25 (masked domain).
     *
     * @param array{0:int,1:int} $cur
     * @param array{0:int,1:int} $key
     * @param array{0:int,1:int} $data
     * @return array{0:int,1:int}
     */
    private static function poly64(array $cur, array $key, array $data): array
    {
        [$keyHi, $keyLo] = $key;
        [$curHi, $curLo] = $cur;

        $x = $keyHi * $curLo + $curHi * $keyLo;   // < 2^58, native
        $xLo = $x & 0xffffffff;
        $xHi = $x >> 32;

        $res = ($keyHi * $curHi + $xHi) * 59 + $keyLo * $curLo; // < 2^63, native
        $r = [$res >> 32, $res & 0xffffffff];

        // res += (x_lo << 32); if it wrapped mod 2^64, add 59.
        $sumHi = $r[0] + $xLo;
        if ($sumHi > 0xffffffff) {
            $r = self::addSmall([$sumHi & 0xffffffff, $r[1]], 59);
        } else {
            $r = [$sumHi, $r[1]];
        }

        // res += data; if it wrapped mod 2^64, add 59.
        $a = self::add($r, $data);
        $r = [$a[0], $a[1]];
        if ($a[2] !== 0) {
            $r = self::addSmall($r, 59);
        }

        return $r;
    }

    // ---- inner-product hash ----

    /**
     * One stream's ip hash word: ip_aux over the four 16-bit chunks of the 64-bit input, reduced
     * mod p36. The accumulator stays well under 2^63, so native ints suffice.
     *
     * @param array{0:int,1:int} $data
     */
    private function ipWord(int $stream, array $data): int
    {
        $b = $stream * 4;
        $t = $this->ipKeys[$b] * (($data[0] >> 16) & 0xffff)
            + $this->ipKeys[$b + 1] * ($data[0] & 0xffff)
            + $this->ipKeys[$b + 2] * (($data[1] >> 16) & 0xffff)
            + $this->ipKeys[$b + 3] * ($data[1] & 0xffff);

        $ret = ($t & self::M36) + 5 * ($t >> 36);
        if ($ret >= self::P36) {
            $ret -= self::P36;
        }

        return $ret & 0xffffffff;
    }

    // ---- PDF (pad derivation) ----

    private function pdfXor(string $nonce, string $tag): string
    {
        $tl = $this->taglen;
        $mask = $tl === 4 ? 3 : ($tl === 8 ? 1 : 0);
        $n7 = ord($nonce[7]);
        $ndx = $mask !== 0 ? ($n7 & $mask) : 0;
        $block = substr($nonce, 0, 7) . chr($n7 & (~$mask & 0xff)) . str_repeat("\x00", 8);
        $cache = self::aes($this->pdfKey, $block);
        $pad = ($tl === 4 || $tl === 8) ? substr($cache, $ndx * $tl, $tl) : substr($cache, 0, $tl);

        return $tag ^ $pad;
    }

    // ---- primitives ----

    /** KDF (umac.c): AES-ECB of a block that is all-zero but for byte 7 = index and byte 15 = counter. */
    private static function kdf(string $key, int $ndx, int $nbytes): string
    {
        $out = '';
        $ctr = 1;
        while (strlen($out) < $nbytes) {
            $block = str_repeat("\x00", 7) . chr($ndx) . str_repeat("\x00", 7) . chr($ctr & 0xff);
            $out .= self::aes($key, $block);
            $ctr++;
        }

        return substr($out, 0, $nbytes);
    }

    private static function aes(string $key, string $block): string
    {
        $out = openssl_encrypt($block, 'aes-128-ecb', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
        if ($out === false) {
            throw new \RuntimeException('ssh: UMAC AES failed');
        }

        return $out;
    }

    /** (hi·2^32 + lo) mod p36 (2^36-5), without 64-bit overflow. */
    private static function modP36(int $hi, int $lo): int
    {
        $a = $hi >> 4;                       // value >> 36
        $b = (($hi & 0xf) << 32) | $lo;      // value & (2^36 - 1)

        return ($b + 5 * $a) % self::P36;
    }

    /** 32×32 → 64-bit product as [hi,lo]. */
    private static function mul(int $a, int $b): array
    {
        $aL = $a & 0xffff;
        $aH = $a >> 16;
        $bL = $b & 0xffff;
        $bH = $b >> 16;
        $ll = $aL * $bL;
        $mid = $aH * $bL + $aL * $bH + ($ll >> 16);

        return [($aH * $bH + ($mid >> 16)) & 0xffffffff, (($ll & 0xffff) | (($mid & 0xffff) << 16)) & 0xffffffff];
    }

    /**
     * 64-bit add: [hi,lo] + [hi,lo] → [hi,lo,carry].
     *
     * @param array{0:int,1:int} $x
     * @param array{0:int,1:int} $y
     * @return array{0:int,1:int,2:int}
     */
    private static function add(array $x, array $y): array
    {
        $lo = $x[1] + $y[1];
        $carry = $lo >> 32;
        $hi = $x[0] + $y[0] + $carry;

        return [$hi & 0xffffffff, $lo & 0xffffffff, $hi >> 32];
    }

    /**
     * @param array{0:int,1:int} $x
     * @return array{0:int,1:int}
     */
    private static function addSmall(array $x, int $n): array
    {
        $lo = $x[1] + $n;

        return [($x[0] + ($lo >> 32)) & 0xffffffff, $lo & 0xffffffff];
    }

    /**
     * @param array{0:int,1:int} $a
     * @param array{0:int,1:int} $b
     */
    private static function cmp(array $a, array $b): int
    {
        if ($a[0] !== $b[0]) {
            return $a[0] < $b[0] ? -1 : 1;
        }
        if ($a[1] !== $b[1]) {
            return $a[1] < $b[1] ? -1 : 1;
        }

        return 0;
    }

    /**
     * @param array{0:int,1:int} $a
     * @param array{0:int,1:int} $b
     * @return array{0:int,1:int}
     */
    private static function sub(array $a, array $b): array
    {
        $lo = $a[1] - $b[1];
        $borrow = 0;
        if ($lo < 0) {
            $lo += 0x100000000;
            $borrow = 1;
        }
        $hi = $a[0] - $b[0] - $borrow;
        if ($hi < 0) {
            $hi += 0x100000000;
        }

        return [$hi, $lo];
    }
}
