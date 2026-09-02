<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh\Cipher;

/**
 * AES-GCM for `aes128-gcm@openssh.com` / `aes256-gcm@openssh.com`, per RFC 5647 §7.1 and OpenSSH
 * cipher.c (`EVP_CTRL_GCM_IV_GEN` / `ctr64_inc`). The 4-byte packet length is authenticated in the
 * clear as AAD and excluded from pad alignment (aadLen 4); the 16-byte tag trails the ciphertext.
 *
 * The 12-byte IV is fixed(4) ‖ invocation_counter(8); the initial value is the derived IV and the
 * 64-bit big-endian invocation field (bytes 4..11) is incremented by one after every packet, the
 * fixed field untouched. GCM nonce reuse is catastrophic, so ONE instance serves ONE direction and
 * the sequence number is ignored (the invocation counter is the per-packet state).
 */
final class Gcm implements PacketCipher
{
    private int $bits;

    /** @param string $key 16 or 32 bytes; @param string $iv 12 bytes (fixed4 ‖ invocation8) from the KDF */
    public function __construct(private string $key, private string $iv)
    {
        // OpenSSH/RFC 5647 define only aes128/256-gcm; a 24-byte path is dead code no client reaches.
        $this->bits = match (strlen($key)) {
            16 => 128,
            32 => 256,
            default => throw new \InvalidArgumentException('ssh: gcm key must be 16 or 32 bytes'),
        };
        if (strlen($iv) !== 12) {
            throw new \InvalidArgumentException('ssh: gcm iv must be 12 bytes');
        }
    }

    public function blockSize(): int
    {
        return 16;
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
        /** @var array{1:int} $u */
        $u = unpack('N', substr($head, 0, 4));

        return $u[1];
    }

    public function seal(int $seq, string $packet): string
    {
        $aad = substr($packet, 0, 4);
        $tag = '';
        $ct = openssl_encrypt(substr($packet, 4), "aes-{$this->bits}-gcm", $this->key, OPENSSL_RAW_DATA, $this->iv, $tag, $aad, 16);
        if ($ct === false) {
            throw new \RuntimeException('ssh: gcm encrypt failed');
        }
        $this->incrementIv();

        return $aad . $ct . $tag;
    }

    public function open(int $seq, string $wire): string
    {
        $aad = substr($wire, 0, 4);
        $ct = substr($wire, 4, strlen($wire) - 4 - 16);
        $tag = substr($wire, strlen($wire) - 16);
        $plain = openssl_decrypt($ct, "aes-{$this->bits}-gcm", $this->key, OPENSSL_RAW_DATA, $this->iv, $tag, $aad);
        if ($plain === false) {
            throw new \RuntimeException('ssh: AEAD tag verification failed');
        }
        $this->incrementIv();

        return $aad . $plain;
    }

    /** The current 12-byte IV — for tests pinning the invocation-counter advance. */
    public function iv(): string
    {
        return $this->iv;
    }

    /** Increment the 64-bit big-endian invocation counter (bytes 4..11); the fixed field is untouched. */
    private function incrementIv(): void
    {
        for ($i = 11; $i >= 4; $i--) {
            $c = (ord($this->iv[$i]) + 1) & 0xff;
            $this->iv[$i] = chr($c);
            if ($c !== 0) {
                break;
            }
        }
    }
}
