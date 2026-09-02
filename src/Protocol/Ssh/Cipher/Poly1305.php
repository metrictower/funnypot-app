<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh\Cipher;

/**
 * Poly1305 one-time authenticator, RFC 8439 §2.5. Pure PHP because ext-sodium exposes no
 * crypto_onetimeauth and no plain (8-byte-nonce) chacha20 stream. The accumulator is five 26-bit
 * limbs held in 64-bit integers, following poly1305-donna's 32-bit reference: each per-block
 * product is < 2^55 (an h_i < 2^27 times an r_i/s_i < 2^28.3) and the five-term sum < 2^58,
 * comfortably inside a signed 64-bit int, so nothing promotes to float on 64-bit PHP.
 *
 * The class REQUIRES 64-bit PHP (the overflow bound assumes it); it throws otherwise. Callers
 * compare the returned tag with hash_equals() — this function is not itself constant-time over the
 * message, but its finalisation branch (the h vs h-p select) is branch-free because the sign of g4
 * is secret-dependent.
 */
final class Poly1305
{
    /** @param string $key32 the 32-byte one-time key (r ‖ s); @param string $msg the message to authenticate */
    public static function mac(string $key32, string $msg): string
    {
        if (PHP_INT_SIZE !== 8) {
            throw new \RuntimeException('ssh: Poly1305 requires 64-bit PHP');
        }
        if (strlen($key32) !== 32) {
            throw new \InvalidArgumentException('ssh: Poly1305 key must be 32 bytes');
        }

        // Clamp r (key[0:16]) into five 26-bit limbs (poly1305-donna clamp constants).
        /** @var array{1:int,2:int,3:int,4:int} $t */
        $t = unpack('V4', substr($key32, 0, 16));
        $t0 = $t[1];
        $t1 = $t[2];
        $t2 = $t[3];
        $t3 = $t[4];
        $r0 = $t0 & 0x3ffffff;
        $r1 = (($t0 >> 26) | ($t1 << 6)) & 0x3ffff03;
        $r2 = (($t1 >> 20) | ($t2 << 12)) & 0x3ffc0ff;
        $r3 = (($t2 >> 14) | ($t3 << 18)) & 0x3f03fff;
        $r4 = ($t3 >> 8) & 0x00fffff;
        $s1 = $r1 * 5;
        $s2 = $r2 * 5;
        $s3 = $r3 * 5;
        $s4 = $r4 * 5;

        $h0 = $h1 = $h2 = $h3 = $h4 = 0;

        $len = strlen($msg);
        $off = 0;
        while ($off < $len) {
            $n = $len - $off;
            if ($n >= 16) {
                $block = substr($msg, $off, 16);
                $hibit = 1 << 24; // the 2^128 bit for a full block
            } else {
                // Final partial block: append 0x01 then zero-pad to 16 bytes; no high bit.
                $block = substr($msg, $off) . "\x01" . str_repeat("\x00", 15 - $n);
                $hibit = 0;
            }
            $off += 16;

            /** @var array{1:int,2:int,3:int,4:int} $m */
            $m = unpack('V4', $block);
            $m0 = $m[1];
            $m1 = $m[2];
            $m2 = $m[3];
            $m3 = $m[4];
            $h0 += $m0 & 0x3ffffff;
            $h1 += ((($m1 << 6) | ($m0 >> 26))) & 0x3ffffff;
            $h2 += ((($m2 << 12) | ($m1 >> 20))) & 0x3ffffff;
            $h3 += ((($m3 << 18) | ($m2 >> 14))) & 0x3ffffff;
            $h4 += ($m3 >> 8) | $hibit;

            // d = h * r  (mod 2^130 - 5), schoolbook with the s_i = 5*r_i wrap terms.
            $d0 = $h0 * $r0 + $h1 * $s4 + $h2 * $s3 + $h3 * $s2 + $h4 * $s1;
            $d1 = $h0 * $r1 + $h1 * $r0 + $h2 * $s4 + $h3 * $s3 + $h4 * $s2;
            $d2 = $h0 * $r2 + $h1 * $r1 + $h2 * $r0 + $h3 * $s4 + $h4 * $s3;
            $d3 = $h0 * $r3 + $h1 * $r2 + $h2 * $r1 + $h3 * $r0 + $h4 * $s4;
            $d4 = $h0 * $r4 + $h1 * $r3 + $h2 * $r2 + $h3 * $r1 + $h4 * $r0;

            $c = $d0 >> 26;
            $h0 = $d0 & 0x3ffffff;
            $d1 += $c;
            $c = $d1 >> 26;
            $h1 = $d1 & 0x3ffffff;
            $d2 += $c;
            $c = $d2 >> 26;
            $h2 = $d2 & 0x3ffffff;
            $d3 += $c;
            $c = $d3 >> 26;
            $h3 = $d3 & 0x3ffffff;
            $d4 += $c;
            $c = $d4 >> 26;
            $h4 = $d4 & 0x3ffffff;
            $h0 += $c * 5;
            $c = $h0 >> 26;
            $h0 &= 0x3ffffff;
            $h1 += $c;
        }

        // Fully carry h.
        $c = $h1 >> 26;
        $h1 &= 0x3ffffff;
        $h2 += $c;
        $c = $h2 >> 26;
        $h2 &= 0x3ffffff;
        $h3 += $c;
        $c = $h3 >> 26;
        $h3 &= 0x3ffffff;
        $h4 += $c;
        $c = $h4 >> 26;
        $h4 &= 0x3ffffff;
        $h0 += $c * 5;
        $c = $h0 >> 26;
        $h0 &= 0x3ffffff;
        $h1 += $c;

        // Compute h + (-p) = h + 5 - 2^130; the borrow in g4 tells us whether h >= p.
        $g0 = $h0 + 5;
        $c = $g0 >> 26;
        $g0 &= 0x3ffffff;
        $g1 = $h1 + $c;
        $c = $g1 >> 26;
        $g1 &= 0x3ffffff;
        $g2 = $h2 + $c;
        $c = $g2 >> 26;
        $g2 &= 0x3ffffff;
        $g3 = $h3 + $c;
        $c = $g3 >> 26;
        $g3 &= 0x3ffffff;
        $g4 = $h4 + $c - (1 << 26);

        // Branch-free select: g4 < 0 → borrow → keep h (mask 0); g4 >= 0 → h >= p → take g (mask -1).
        // PHP >> is arithmetic, so ($g4 >> 63) is -1 for negative g4; (& 1) - 1 maps it to {0, -1}.
        $mask = (($g4 >> 63) & 1) - 1;
        $g0 &= $mask;
        $g1 &= $mask;
        $g2 &= $mask;
        $g3 &= $mask;
        $g4 &= $mask;
        $nmask = ~$mask;
        $h0 = ($h0 & $nmask) | $g0;
        $h1 = ($h1 & $nmask) | $g1;
        $h2 = ($h2 & $nmask) | $g2;
        $h3 = ($h3 & $nmask) | $g3;
        $h4 = ($h4 & $nmask) | $g4;

        // Pack the five limbs into four 32-bit little-endian words.
        $f0 = ($h0 | ($h1 << 26)) & 0xffffffff;
        $f1 = (($h1 >> 6) | ($h2 << 20)) & 0xffffffff;
        $f2 = (($h2 >> 12) | ($h3 << 14)) & 0xffffffff;
        $f3 = (($h3 >> 18) | ($h4 << 8)) & 0xffffffff;

        // Add s (key[16:32]) modulo 2^128 with 32-bit carries.
        /** @var array{1:int,2:int,3:int,4:int} $sk */
        $sk = unpack('V4', substr($key32, 16, 16));
        $f = $f0 + $sk[1];
        $f0 = $f & 0xffffffff;
        $f = $f1 + $sk[2] + ($f >> 32);
        $f1 = $f & 0xffffffff;
        $f = $f2 + $sk[3] + ($f >> 32);
        $f2 = $f & 0xffffffff;
        $f = $f3 + $sk[4] + ($f >> 32);
        $f3 = $f & 0xffffffff;

        return pack('V4', $f0, $f1, $f2, $f3);
    }
}
