<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh\Cipher;

/**
 * One direction of an SSH binary-packet cipher (RFC 4253 §6): it seals a fully padded plaintext
 * packet into wire bytes and opens wire bytes back into the plaintext packet, plus the four shape
 * constants {@see Transport} needs to build the padding and slice the receive buffer. Every method
 * takes the packet sequence number; ciphers that key their per-packet nonce on other state (GCM's
 * invocation counter) ignore it. Padding is NOT the cipher's job — {@see Transport::padLen()} owns
 * the one aadlen-aware rule and hands `seal()` the already-padded `len‖padlen‖payload‖pad` packet.
 */
interface PacketCipher
{
    /** Pad-alignment block, >= 8: 16 for AES modes, 8 for chacha20-poly1305 and plaintext. */
    public function blockSize(): int;

    /** Leading bytes excluded from pad alignment, carried as AAD/clear: 4 for ETM/GCM/chacha, 0 for E&M/plain. */
    public function aadLen(): int;

    /** Trailing bytes after the ciphertext: HMAC length (E&M/ETM), 16 (AEAD tag), 0 (plain). */
    public function tagLen(): int;

    /** Bytes of wire the receiver needs before peekLength(): blockSize() for E&M (first-block decrypt), 4 otherwise. */
    public function headLen(): int;

    /** packet_length from the first headLen() bytes. No bounds/alignment validation (Transport does it). */
    public function peekLength(int $seq, string $head): int;

    /** Seal one plaintext packet (uint32 packet_length ‖ byte padlen ‖ payload ‖ pad) → wire bytes incl. MAC/tag. */
    public function seal(int $seq, string $packet): string;

    /** Open one complete wire packet (4 + packet_length + tagLen() bytes) → plaintext packet. Throws on MAC/tag failure. */
    public function open(int $seq, string $wire): string;
}
