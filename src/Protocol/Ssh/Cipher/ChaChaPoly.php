<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh\Cipher;

/**
 * chacha20-poly1305@openssh.com, per OpenSSH PROTOCOL.chacha20poly1305 and cipher-chachapoly.c
 * (`chachapoly_crypt`). The 64-byte derived key is K_2 ‖ K_1: K_2 = key[0:32] encrypts the payload
 * and derives the Poly1305 key; K_1 = key[32:64] encrypts the 4-byte length field on its own. The
 * length is excluded from pad alignment (aadLen 4, block 8); the 16-byte Poly1305 tag trails.
 *
 * The per-packet nonce is the sequence number as a big-endian uint64 (`POKE_U64(seqbuf, seqnr)`).
 * ChaCha20 runs through ext-openssl's `chacha20`, whose 16-byte IV is LE64(counter) ‖ 8-byte nonce
 * — verified equivalent to the DJB 64-bit-counter cipher including the 2^32 block crossing. The
 * tag is verified BEFORE the body is decrypted (the length is necessarily decrypted first to slice
 * the wire, exactly as OpenSSH does; Transport's MAX_PACKET/alignment check bounds it).
 */
final class ChaChaPoly implements PacketCipher
{
    private string $kMain;   // K_2: payload + Poly1305 key
    private string $kHeader; // K_1: length field

    /** @param string $key the 64-byte derived key (K_2 ‖ K_1) */
    public function __construct(string $key)
    {
        if (strlen($key) !== 64) {
            throw new \InvalidArgumentException('ssh: chacha20-poly1305 key must be 64 bytes');
        }
        $this->kMain = substr($key, 0, 32);
        $this->kHeader = substr($key, 32, 32);
    }

    public function blockSize(): int
    {
        return 8;
    }

    public function aadLen(): int
    {
        return 4;
    }

    public function tagLen(): int
    {
        return 16;
    }

    public function headLen(): int
    {
        return 4;
    }

    public function peekLength(int $seq, string $head): int
    {
        $clear = self::chacha20($this->kHeader, 0, pack('J', $seq), substr($head, 0, 4));
        /** @var array{1:int} $u */
        $u = unpack('N', $clear);

        return $u[1];
    }

    public function seal(int $seq, string $packet): string
    {
        $nonce = pack('J', $seq);
        $polyKey = substr(self::chacha20($this->kMain, 0, $nonce, str_repeat("\x00", 32)), 0, 32);
        $encLen = self::chacha20($this->kHeader, 0, $nonce, substr($packet, 0, 4));
        $encBody = self::chacha20($this->kMain, 1, $nonce, substr($packet, 4));
        $tag = Poly1305::mac($polyKey, $encLen . $encBody);

        return $encLen . $encBody . $tag;
    }

    public function open(int $seq, string $wire): string
    {
        $nonce = pack('J', $seq);
        $ctLen = strlen($wire) - 16;
        $tag = substr($wire, $ctLen);
        $polyKey = substr(self::chacha20($this->kMain, 0, $nonce, str_repeat("\x00", 32)), 0, 32);
        $calc = Poly1305::mac($polyKey, substr($wire, 0, $ctLen));
        if (!hash_equals($calc, $tag)) {
            throw new \RuntimeException('ssh: AEAD tag verification failed');
        }
        $clearLen = self::chacha20($this->kHeader, 0, $nonce, substr($wire, 0, 4));
        $body = self::chacha20($this->kMain, 1, $nonce, substr($wire, 4, $ctLen - 4));

        return $clearLen . $body;
    }

    /**
     * DJB ChaCha20 (64-bit nonce, 64-bit block counter) via OpenSSL: its 16-byte IV is
     * LE64(counter) ‖ 8-byte nonce.
     */
    private static function chacha20(string $key, int $ctr, string $nonce8, string $data): string
    {
        if ($data === '') {
            return '';
        }
        $out = openssl_encrypt($data, 'chacha20', $key, OPENSSL_RAW_DATA, pack('P', $ctr) . $nonce8);
        if ($out === false) {
            throw new \RuntimeException('ssh: chacha20 keystream failed');
        }

        return $out;
    }
}
