<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh\Cipher;

/**
 * The pre-NEWKEYS state of both directions: RFC 4253 §6 framing with no encryption and no MAC.
 * Block 8 / aadLen 0 / tagLen 0 / headLen 4; seal and open are the identity, so {@see Transport}
 * runs one code path whether or not keys are installed. The 8-byte alignment (length included)
 * matches OpenSSH's plaintext KEX packets.
 */
final class PlainCipher implements PacketCipher
{
    public function blockSize(): int
    {
        return 8;
    }

    public function aadLen(): int
    {
        return 0;
    }

    public function tagLen(): int
    {
        return 0;
    }

    public function headLen(): int
    {
        return 4;
    }

    public function peekLength(int $seq, string $head): int
    {
        /** @var array{1:int} $u */
        $u = unpack('N', substr($head, 0, 4));

        return $u[1];
    }

    public function seal(int $seq, string $packet): string
    {
        return $packet;
    }

    public function open(int $seq, string $wire): string
    {
        return $wire;
    }
}
