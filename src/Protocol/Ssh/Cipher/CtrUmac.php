<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh\Cipher;

use Funnypot\Protocol\Ssh\Ctr;

/**
 * AES-CTR with a UMAC (umac-64/umac-128(@openssh.com), E&M and ETM), the UMAC counterpart of
 * {@see CtrHmac}. The wire layout is identical to CtrHmac; only the MAC differs (OpenSSH mac.c):
 * the packet sequence number is carried in the UMAC nonce (8 bytes, big-endian), and the
 * authenticated data carries NO seqno prefix — the opposite of HMAC, which prepends BE32(seq).
 *
 *  - E&M (aadLen 0): MAC = UMAC(nonce=seq, plaintext_packet). The first block is decrypted in
 *    peekLength() to learn the length and cached for open().
 *  - ETM (aadLen 4): the 4-byte length is clear; MAC = UMAC(nonce=seq, clear_length ‖ ciphertext),
 *    verified before any decrypt.
 */
final class CtrUmac implements PacketCipher
{
    private int $tagLen;

    private ?int $cacheSeq = null;
    private ?string $cacheBlock = null;

    public function __construct(
        private Ctr $ctr,
        private Umac $umac,
        int $tagLen,
        private bool $etm
    ) {
        $this->tagLen = $tagLen;
    }

    public function blockSize(): int
    {
        return 16;
    }

    public function aadLen(): int
    {
        return $this->etm ? 4 : 0;
    }

    public function tagLen(): int
    {
        return $this->tagLen;
    }

    public function headLen(): int
    {
        return $this->etm ? 4 : 16;
    }

    public function peekLength(int $seq, string $head): int
    {
        if ($this->etm) {
            /** @var array{1:int} $u */
            $u = unpack('N', substr($head, 0, 4));

            return $u[1];
        }
        $first = $this->ctr->crypt(substr($head, 0, 16));
        $this->cacheSeq = $seq;
        $this->cacheBlock = $first;
        /** @var array{1:int} $u */
        $u = unpack('N', substr($first, 0, 4));

        return $u[1];
    }

    public function seal(int $seq, string $packet): string
    {
        if ($this->etm) {
            $ct = $this->ctr->crypt(substr($packet, 4));
            $mac = $this->umac->compute(self::nonce($seq), substr($packet, 0, 4) . $ct);

            return substr($packet, 0, 4) . $ct . $mac;
        }
        $ct = $this->ctr->crypt($packet);
        $mac = $this->umac->compute(self::nonce($seq), $packet);

        return $ct . $mac;
    }

    public function open(int $seq, string $wire): string
    {
        $ctLen = strlen($wire) - $this->tagLen;
        $tag = substr($wire, $ctLen);

        if ($this->etm) {
            $clearLen = substr($wire, 0, 4);
            $calc = $this->umac->compute(self::nonce($seq), substr($wire, 0, $ctLen));
            if (!hash_equals($calc, $tag)) {
                throw new \RuntimeException('ssh: MAC verification failed');
            }

            return $clearLen . $this->ctr->crypt(substr($wire, 4, $ctLen - 4));
        }

        if ($this->cacheBlock !== null) {
            if ($this->cacheSeq !== $seq) {
                throw new \RuntimeException('ssh: cipher state desync');
            }
            $first = $this->cacheBlock;
            $this->cacheSeq = null;
            $this->cacheBlock = null;
        } else {
            $first = $this->ctr->crypt(substr($wire, 0, 16));
        }
        $rest = substr($wire, 16, $ctLen - 16);
        $plain = $first . ($rest === '' ? '' : $this->ctr->crypt($rest));
        $calc = $this->umac->compute(self::nonce($seq), $plain);
        if (!hash_equals($calc, $tag)) {
            throw new \RuntimeException('ssh: MAC verification failed');
        }

        return $plain;
    }

    /** The 8-byte big-endian UMAC nonce for a 32-bit SSH sequence number (OpenSSH POKE_U64). */
    private static function nonce(int $seq): string
    {
        return "\x00\x00\x00\x00" . pack('N', $seq);
    }
}
