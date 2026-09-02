<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh;

/**
 * Streaming AES-CTR keystream, the transport cipher for aes128/192/256-ctr. PHP's one-shot
 * openssl_encrypt cannot carry counter state across SSH packets, so this wraps it: each call
 * encrypts $data under aes-{128,192,256}-ctr seeded with the current 128-bit big-endian counter,
 * then advances the counter by ceil(len/16) blocks so the next packet resumes the keystream in
 * step. SSH packets are always block-aligned, but a partial final block still consumes one full
 * keystream block (openssl semantics), which the +ceil advance mirrors exactly.
 *
 * Encryption and decryption are the same operation (XOR), so one class serves both directions.
 */
final class Ctr
{
    private string $method;

    public function __construct(private string $key, private string $counter)
    {
        // A 24-byte key formerly ran aes-128-ecb and silently used only the first 16 bytes; reject
        // any non-standard length outright so aes192-ctr (FP-0291) cannot be truncated in secret.
        $this->method = match (strlen($key)) {
            16 => 'aes-128-ctr',
            24 => 'aes-192-ctr',
            32 => 'aes-256-ctr',
            default => throw new \InvalidArgumentException('ssh: aes key must be 16/24/32 bytes'),
        };
    }

    public function crypt(string $data): string
    {
        $len = strlen($data);
        if ($len === 0) {
            return '';
        }
        $out = openssl_encrypt(
            $data,
            $this->method,
            $this->key,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $this->counter
        );
        if ($out === false) {
            throw new \RuntimeException('ssh: aes-ctr keystream failed');
        }
        $this->advance(intdiv($len + 15, 16));

        return $out;
    }

    /** Advance the 128-bit big-endian counter by $blocks, carrying across all 16 bytes. */
    private function advance(int $blocks): void
    {
        for ($i = 15; $i >= 0 && $blocks > 0; $i--) {
            $sum = ord($this->counter[$i]) + ($blocks & 0xff);
            $this->counter[$i] = chr($sum & 0xff);
            $blocks = ($blocks >> 8) + ($sum >> 8); // remaining high bytes + carry
        }
    }
}
