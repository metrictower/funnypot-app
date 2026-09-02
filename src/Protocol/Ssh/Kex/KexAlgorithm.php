<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh\Kex;

/**
 * One key-exchange algorithm's server side, driven by the inbound kex-phase messages (30/32/34).
 * A concrete algorithm is built once per connection from the negotiated name (see {@see KexSuite})
 * and fed each kex message in turn; it owns the msg-30 collision — the caller routes the raw number
 * and never decides what "30" means, so a client's KEX_ECDH_INIT, KEXDH_INIT and (unsupported)
 * GEX_REQUEST_OLD are all "30" but only the negotiated object knows which one to expect.
 */
interface KexAlgorithm
{
    /** The negotiated SSH kex name (e.g. 'curve25519-sha256'). */
    public function name(): string;

    /**
     * The kex hash: 'sha256' | 'sha384' | 'sha512'. RFC 4253 §7.2 uses it for key derivation too,
     * so {@see KexResult::keys()} feeds it straight to {@see \Funnypot\Protocol\Ssh\KeyDerivation}.
     */
    public function hashAlgo(): string;

    /**
     * Feed one inbound kex-phase message (30/32/34); $payload includes the leading message byte.
     * Returns the reply payload(s) to send, in order; returns NULL when this message is not expected
     * in the current state (the caller answers SSH_MSG_UNIMPLEMENTED, mirroring sshd
     * kex_protocol_error) — and MUST NOT mutate state on a null return, so a stray message never
     * disturbs a later valid one. Throws \RuntimeException when an expected message is malformed or
     * its values are invalid (the caller disconnects with a protocol error).
     *
     * @return string[]|null
     */
    public function handle(int $msg, string $payload): ?array;

    /** Non-null once the exchange hash is signed; after that handle() returns null for everything. */
    public function result(): ?KexResult;
}
