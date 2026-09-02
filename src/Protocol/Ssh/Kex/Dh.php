<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh\Kex;

use Funnypot\Protocol\Ssh\Buf;
use Funnypot\Protocol\Ssh\Reader;

/**
 * Fixed-group finite-field Diffie-Hellman: diffie-hellman-group14-sha256, group16-sha512 and
 * group18-sha512 (RFC 4253 §8 / RFC 8268), on ext-openssl with an embedded RFC 3526 modulus. One
 * inbound message is expected — 30 (KEXDH_INIT, `mpint e`) — answered with 31 (KEXDH_REPLY:
 * `string K_S, mpint f, string sig`); anything else, or a second 30, returns null.
 *
 * The same message number 30 is KEX_ECDH_INIT for an ECDH kex; the caller routes it to whichever
 * kex object was negotiated, so a 256-byte group-14 `e` is never fed to X25519 and vice versa.
 */
final class Dh extends AbstractKex
{
    use DhComputation;

    private const MSG_KEXDH_INIT = 30;
    private const MSG_KEXDH_REPLY = 31;

    public function handle(int $msg, string $payload): ?array
    {
        if ($this->result !== null || $msg !== self::MSG_KEXDH_INIT) {
            return null;
        }
        $p = DhGroups::modulus($this->groupBits());

        $r = new Reader($payload);
        $r->byte();
        $e = $r->mpint(); // throws on a negative mpint (sshd BN_is_negative)
        $this->validatePeerValue($e, $p);

        [$ours, $f] = $this->dhKeypair($p);
        $k = $this->dhDerive($p, $e, $ours);
        $kMpint = Buf::mpintOf($k);

        // sshd re-encodes the parsed e canonically (put_bignum2) before hashing, so a non-canonical
        // client encoding is normalised, not echoed.
        $hashInput = $this->hashPrefix()
            . Buf::mpintOf($e)
            . Buf::mpintOf($f)
            . $kMpint;
        $sig = $this->finish($hashInput, $kMpint);

        $reply = (new Buf())
            ->byte(self::MSG_KEXDH_REPLY)
            ->string($this->hostKey->publicBlob())
            ->mpint($f)
            ->string($sig)
            ->get();

        return [$reply];
    }

    private function groupBits(): int
    {
        return match ($this->name) {
            'diffie-hellman-group14-sha256' => 2048,
            'diffie-hellman-group16-sha512' => 4096,
            'diffie-hellman-group18-sha512' => 8192,
            default => throw new \RuntimeException("ssh: unsupported dh group {$this->name}"),
        };
    }
}
