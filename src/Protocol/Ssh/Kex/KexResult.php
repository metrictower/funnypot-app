<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh\Kex;

use Funnypot\Protocol\Ssh\Cipher\CipherSuite;
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

    /**
     * Derive the six directional materials sized per the negotiated cipher/MAC of EACH direction
     * (RFC 4253 §7.2 letters A–F are per direction, and a client may negotiate different ciphers/MACs
     * each way). For an AEAD cipher the MAC key is still derived and discarded, exactly as sshd does.
     *
     * @return array{ivC2S:string,ivS2C:string,keyC2S:string,keyS2C:string,macC2S:string,macS2C:string}
     */
    public function keysFor(string $encC2S, string $macC2S, string $encS2C, string $macS2C): array
    {
        $d = fn (string $letter, int $need): string => KeyDerivation::derive(
            $this->hashAlgo,
            $this->kEncoded,
            $this->exchangeHash,
            $this->exchangeHash,
            $letter,
            $need
        );

        return [
            'ivC2S' => $d('A', CipherSuite::ivLen($encC2S)),
            'ivS2C' => $d('B', CipherSuite::ivLen($encS2C)),
            'keyC2S' => $d('C', CipherSuite::keyLen($encC2S)),
            'keyS2C' => $d('D', CipherSuite::keyLen($encS2C)),
            'macC2S' => $d('E', CipherSuite::macKeyLen($macC2S)),
            'macS2C' => $d('F', CipherSuite::macKeyLen($macS2C)),
        ];
    }
}
