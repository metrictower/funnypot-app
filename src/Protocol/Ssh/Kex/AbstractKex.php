<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh\Kex;

use Funnypot\Protocol\Ssh\Buf;
use Funnypot\Protocol\Ssh\HostKey\HostKeyAlgorithm;

/**
 * Shared context and exchange-hash machinery for the concrete kex algorithms. Holds the two version
 * strings, both KEXINIT payloads and the host key — everything that goes into the hash prefix
 * V_C ‖ V_S ‖ I_C ‖ I_S ‖ K_S (RFC 4253 §8, common to every kex in this ticket) — plus the result
 * once the exchange hash is signed.
 */
abstract class AbstractKex implements KexAlgorithm
{
    protected ?KexResult $result = null;

    public function __construct(
        protected string $name,
        protected string $hashAlgo,
        protected string $vC,
        protected string $vS,
        protected string $iC,
        protected string $iS,
        protected HostKeyAlgorithm $hostKey
    ) {
    }

    public function name(): string
    {
        return $this->name;
    }

    public function hashAlgo(): string
    {
        return $this->hashAlgo;
    }

    public function result(): ?KexResult
    {
        return $this->result;
    }

    /** The exchange-hash prefix shared by every algorithm: string V_C ‖ V_S ‖ I_C ‖ I_S ‖ K_S. */
    protected function hashPrefix(): string
    {
        return Buf::stringOf($this->vC)
            . Buf::stringOf($this->vS)
            . Buf::stringOf($this->iC)
            . Buf::stringOf($this->iS)
            . Buf::stringOf($this->hostKey->publicBlob());
    }

    /**
     * Hash the assembled input to H, store the result (K as $kEncoded), and return the host-key
     * signature over H — the signature blob the reply carries.
     */
    protected function finish(string $hashInput, string $kEncoded): string
    {
        $h = hash($this->hashAlgo, $hashInput, true);
        $this->result = new KexResult($this->hashAlgo, $kEncoded, $h);

        return $this->hostKey->sign($h);
    }
}
