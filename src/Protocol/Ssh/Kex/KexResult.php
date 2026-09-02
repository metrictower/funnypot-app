<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh\Kex;

use Funnypot\Protocol\Ssh\KeyDerivation;

/**
 * The outcome of a completed key exchange: the exchange hash H (= the session id for the first and
 * only kex), the shared secret K exactly as the algorithm encoded it into the hash (an mpint for
 * every algorithm in this ticket; a future KEM will pass a raw string), and the kex hash name. It
 * carries no directional key material itself — {@see keys()} derives that on demand, so the caller
 * asks for exactly the sizes the negotiated cipher/MAC need.
 */
final class KexResult
{
    public function __construct(
        public string $hashAlgo,
        public string $kEncoded,
        public string $exchangeHash
    ) {
    }

    /**
     * Derive the six directional materials (RFC 4253 §7.2). session_id == H for the first key
     * exchange, so H is passed for both. For need <= hashlen this is bit-identical to the former
     * one-shot formula.
     *
     * @return array{ivC2S:string,ivS2C:string,keyC2S:string,keyS2C:string,macC2S:string,macS2C:string}
     */
    public function keys(int $ivLen, int $keyLen, int $macLen): array
    {
        return KeyDerivation::deriveAll(
            $this->hashAlgo,
            $this->kEncoded,
            $this->exchangeHash,
            $this->exchangeHash,
            $ivLen,
            $keyLen,
            $macLen
        );
    }
}
