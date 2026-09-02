<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh\HostKey;

/**
 * One host-key signature algorithm the server can offer. A honeypot only ever exposes the public
 * blob (K_S, sent in the kex reply) and signs the exchange hash — it never verifies client
 * signatures. The signature blob it returns is `string algorithm ‖ string sig`, the wire form the
 * kex reply carries.
 */
interface HostKeyAlgorithm
{
    /** The negotiated signature name: 'ssh-ed25519' | 'rsa-sha2-256' | 'rsa-sha2-512' | 'ecdsa-sha2-nistp256'. */
    public function algorithm(): string;

    /** The public-key blob K_S (RFC 4253 §6.6 / RFC 8332 §3 / RFC 5656 §3.1). */
    public function publicBlob(): string;

    /** Signature blob over $data: string algorithm() ‖ string sig. */
    public function sign(string $data): string;
}
