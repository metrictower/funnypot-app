<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh\Cipher;

use Funnypot\Protocol\Ssh\Ctr;

/**
 * AES-CTR with an HMAC, in both SSH MAC modes. Layout copied from OpenSSH mac.c / packet.c
 * (`ssh_packet_send2_wrapped`, `mac_compute`) and RFC 4253 §6.4:
 *
 *  - Encrypt-and-MAC (E&M, aadLen 0): the classic SSH mode for `hmac-sha2-*`. The whole packet
 *    (length field included) is encrypted, and the MAC is HMAC(seq ‖ plaintext_packet). The
 *    receiver must decrypt the first block to learn the length before the rest arrives, so that
 *    first block is cached across peekLength()→open().
 *  - Encrypt-then-MAC (ETM, aadLen 4): the `-etm@openssh.com` twins. The 4-byte length stays in
 *    the clear, the rest is encrypted, and the MAC is HMAC(seq ‖ clear_length ‖ ciphertext). The
 *    tag is verified BEFORE any decrypt (OpenSSH cipher-aesctr / `mac->etm` path) — decrypting
 *    first is the classic ETM mistake.
 */
final class CtrHmac implements PacketCipher
{
    private int $tagLen;

    // E&M only: the first-block decrypt from peekLength(), held until open() for the same seq.
    private ?int $cacheSeq = null;
    private ?string $cacheBlock = null;

    /** @param string $hmacAlgo one of sha1|sha256|sha512 */
    public function __construct(
        private Ctr $ctr,
        private string $hmacAlgo,
        private string $macKey,
        private bool $etm
    ) {
        $this->tagLen = strlen(hash_hmac($hmacAlgo, '', $macKey, true));
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
        // E&M: decrypting the first block advances the keystream, so cache it for open().
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
            $mac = hash_hmac($this->hmacAlgo, pack('N', $seq) . substr($packet, 0, 4) . $ct, $this->macKey, true);

            return substr($packet, 0, 4) . $ct . $mac;
        }
        $ct = $this->ctr->crypt($packet);
        $mac = hash_hmac($this->hmacAlgo, pack('N', $seq) . $packet, $this->macKey, true);

        return $ct . $mac;
    }

    public function open(int $seq, string $wire): string
    {
        $ctLen = strlen($wire) - $this->tagLen;
        $tag = substr($wire, $ctLen);

        if ($this->etm) {
            $clearLen = substr($wire, 0, 4);
            $calc = hash_hmac($this->hmacAlgo, pack('N', $seq) . substr($wire, 0, $ctLen), $this->macKey, true);
            if (!hash_equals($calc, $tag)) {
                throw new \RuntimeException('ssh: MAC verification failed');
            }
            $plain = $clearLen . $this->ctr->crypt(substr($wire, 4, $ctLen - 4));

            return $plain;
        }

        // E&M: reuse the cached first-block decrypt from peekLength() when present.
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
        $calc = hash_hmac($this->hmacAlgo, pack('N', $seq) . $plain, $this->macKey, true);
        if (!hash_equals($calc, $tag)) {
            throw new \RuntimeException('ssh: MAC verification failed');
        }

        return $plain;
    }
}
