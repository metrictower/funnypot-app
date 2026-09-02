<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Protocol\Ssh\Cipher\CipherSuite;
use Funnypot\Protocol\Ssh\Cipher\Umac;
use Funnypot\Protocol\Ssh\Transport;
use PHPUnit\Framework\TestCase;

/**
 * FP-0293a (folded into FP-0291 as commit 2) — UMAC (RFC 4418) known-answer and round-trip tests.
 *
 * The known-answer vectors are the ones published in RFC 4418's appendix (key "abcdefghijklmnop",
 * nonce "bcdefghi"), written here as literals rather than read from the implementation. They cover
 * UMAC-32/64/96; the RFC gives no 128-bit column, but UMAC-128's first 12 bytes equal UMAC-96 by
 * construction (same NH/poly/ip streams 0-2 and the same >8-byte PDF branch — only a fourth,
 * structurally identical stream is added), so the 96-bit vector pins umac-128 too. OpenSSH uses the
 * 8- and 16-byte outputs (umac-64 / umac-128); the 32/96 modes exist here only to exercise every
 * code branch against the authoritative vectors.
 */
final class SshUmacTest extends TestCase
{
    private const KEY = 'abcdefghijklmnop';
    private const NONCE = 'bcdefghi';

    /** @return array<string,array{0:string,1:string,2:string,3:string}> [msg, umac32, umac64, umac96] */
    public function rfc4418Vectors(): array
    {
        return [
            'empty'   => ['',                        '113145FB', '6E155FAD26900BE1', '32FEDB100C79AD58F07FF764'],
            "'a'*3"   => [str_repeat('a', 3),        '3B91D102', '44B5CB542F220104', '185E4FE905CBA7BD85E4C2DC'],
            "'a'*2^10" => [str_repeat('a', 1 << 10), '599B350B', '26BF2F5D60118BD9', '7A54ABE04AF82D60FB298C3C'],
            "'a'*2^15" => [str_repeat('a', 1 << 15), '58DCF532', '27F8EF643B0D118D', '7B136BD911E4B734286EF2BE'],
            "'a'*2^20" => [str_repeat('a', 1 << 20), 'DB6364D1', 'A4477E87E9F55853', 'F8ACFA3AC31CFEEA047F7B11'],
            "'a'*2^25" => [str_repeat('a', 1 << 25), '5109A660', '2E2DBC36860A0A5F', '72C6388BACE3ACE6FBF062D9'],
            "'abc'*1"  => ['abc',                    'ABF3A3A0', 'D4D7B9F6BD4FBFCF', '883C3D4B97A61976FFCF2323'],
            "'abc'*500" => [str_repeat('abc', 500),  'ABEB3C8B', 'D4CF26DDEFD5C01A', '8824A260C53C66A36C9260A6'],
        ];
    }

    /** @dataProvider rfc4418Vectors */
    public function test_umac_matches_rfc4418_vectors(string $msg, string $u32, string $u64, string $u96): void
    {
        self::assertSame($u32, strtoupper(bin2hex((new Umac(self::KEY, 4))->compute(self::NONCE, $msg))), 'UMAC-32');
        self::assertSame($u64, strtoupper(bin2hex((new Umac(self::KEY, 8))->compute(self::NONCE, $msg))), 'UMAC-64');
        self::assertSame($u96, strtoupper(bin2hex((new Umac(self::KEY, 12))->compute(self::NONCE, $msg))), 'UMAC-96');
        // UMAC-128's first 12 bytes are UMAC-96 (shared streams + PDF branch); pins umac-128 to the RFC.
        $u128 = strtoupper(bin2hex((new Umac(self::KEY, 16))->compute(self::NONCE, $msg)));
        self::assertSame($u96, substr($u128, 0, 24), 'UMAC-128[0:12] == UMAC-96');
        self::assertSame(32, strlen($u128), 'UMAC-128 is 16 bytes');
    }

    public function test_nonce_changes_the_tag(): void
    {
        $u = new Umac(self::KEY, 8);
        self::assertNotSame($u->compute("\x00\x00\x00\x00\x00\x00\x00\x01", 'hello'), $u->compute("\x00\x00\x00\x00\x00\x00\x00\x02", 'hello'));
    }

    public function test_cipher_suite_sizes_for_the_four_openssh_names(): void
    {
        foreach (['umac-64@openssh.com', 'umac-64-etm@openssh.com'] as $name) {
            self::assertSame(16, CipherSuite::macKeyLen($name), "{$name} key length is 16");
            self::assertSame(8, CipherSuite::macTagLen($name), "{$name} tag length is 8");
        }
        foreach (['umac-128@openssh.com', 'umac-128-etm@openssh.com'] as $name) {
            self::assertSame(16, CipherSuite::macKeyLen($name), "{$name} key length is 16");
            self::assertSame(16, CipherSuite::macTagLen($name), "{$name} tag length is 16");
        }
        self::assertTrue(CipherSuite::isEtm('umac-64-etm@openssh.com'));
        self::assertFalse(CipherSuite::isEtm('umac-64@openssh.com'));
    }

    /**
     * A full seal→open round trip through the transport for every umac name on aes-CTR, both E&M and
     * ETM, over a range of packet sizes; and a tampered wire fails the MAC. This is the wiring proof
     * that FP-0291's list flip can advertise these names (advertise ⇒ implement).
     *
     * @dataProvider umacCipherRows
     */
    public function test_seal_open_round_trip_and_tamper_rejection(string $cipher, string $mac): void
    {
        $keyLen = CipherSuite::keyLen($cipher);
        $ivLen = CipherSuite::ivLen($cipher);
        $macKey = random_bytes(CipherSuite::macKeyLen($mac));
        $key = random_bytes($keyLen);
        $iv = random_bytes($ivLen);

        $send = new Transport();
        $recv = new Transport();
        $send->enableSend(CipherSuite::build($cipher, $mac, $key, $iv, $macKey));
        $recv->enableRecv(CipherSuite::build($cipher, $mac, $key, $iv, $macKey));

        foreach ([1, 5, 16, 17, 100, 1023, 4096] as $n) {
            $payload = "\x5e" . random_bytes($n);
            $buffer = $send->frame($payload);
            self::assertSame($payload, $recv->next($buffer), "{$cipher}/{$mac} round-trips a {$n}-byte payload");
        }

        // Tamper one ciphertext byte → MAC verification fails, connection would drop.
        $send2 = new Transport();
        $recv2 = new Transport();
        $send2->enableSend(CipherSuite::build($cipher, $mac, $key, $iv, $macKey));
        $recv2->enableRecv(CipherSuite::build($cipher, $mac, $key, $iv, $macKey));
        $wire = $send2->frame("\x5e" . str_repeat('x', 40));
        $wire[20] = chr(ord($wire[20]) ^ 0x01);
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('MAC');
        $recv2->next($wire);
    }

    /** @return array<string,array{0:string,1:string}> */
    public function umacCipherRows(): array
    {
        $rows = [];
        foreach (['aes128-ctr', 'aes256-ctr'] as $cipher) {
            foreach (['umac-64@openssh.com', 'umac-128@openssh.com', 'umac-64-etm@openssh.com', 'umac-128-etm@openssh.com'] as $mac) {
                $rows["{$cipher} + {$mac}"] = [$cipher, $mac];
            }
        }

        return $rows;
    }
}
