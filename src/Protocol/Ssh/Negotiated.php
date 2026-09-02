<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh;

/**
 * The algorithms chosen for one connection (RFC 4253 §7.1 — client-preference-first against the
 * profile's served lists). A plain value object recorded on {@see SshConnection} once negotiation
 * succeeds; the cipher/MAC are per direction because a client may legally negotiate different ones
 * each way (our served lists are symmetric, the client's need not be).
 */
final class Negotiated
{
    public function __construct(
        public string $kex,
        public string $hostKey,
        public string $encC2S,
        public string $encS2C,
        public string $macC2S,
        public string $macS2C,
        public string $compC2S,
        public string $compS2C
    ) {
    }
}
