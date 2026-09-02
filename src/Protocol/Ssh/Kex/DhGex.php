<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh\Kex;

use Funnypot\Protocol\Ssh\Buf;
use Funnypot\Protocol\Ssh\Reader;

/**
 * diffie-hellman-group-exchange-sha256 (RFC 4419), mirroring OpenSSH 8.9 kexgexs.c: the client
 * sends KEX_DH_GEX_REQUEST (34, `uint32 min, n, max`); we answer KEX_DH_GEX_GROUP (31, `mpint p,
 * mpint g`) with the chosen embedded group; the client sends KEX_DH_GEX_INIT (32, `mpint e`) and we
 * answer KEX_DH_GEX_REPLY (33, `string K_S, mpint f, string sig`).
 *
 * 8.9 dropped KEX_DH_GEX_REQUEST_OLD (30) — it is not handled at all, so a 30 in any state returns
 * null (the caller answers SSH_MSG_UNIMPLEMENTED), deliberately matching a real 8.9 box rather than
 * implementing RFC 4419's old-style flow. Wrong-message-for-state (32 before 34, a second 34) also
 * returns null without mutating state.
 */
final class DhGex extends AbstractKex
{
    use DhComputation;

    private const MSG_KEX_DH_GEX_GROUP = 31;
    private const MSG_KEX_DH_GEX_INIT = 32;
    private const MSG_KEX_DH_GEX_REPLY = 33;
    private const MSG_KEX_DH_GEX_REQUEST = 34;

    private const DH_GRP_MIN = 2048;
    private const DH_GRP_MAX = 8192;

    private int $reqMin = 0;
    private int $reqN = 0;
    private int $reqMax = 0;
    private string $chosenP = '';
    private bool $grouped = false;

    public function handle(int $msg, string $payload): ?array
    {
        if ($this->result !== null) {
            return null;
        }
        if (!$this->grouped) {
            return $msg === self::MSG_KEX_DH_GEX_REQUEST ? $this->request($payload) : null;
        }

        return $msg === self::MSG_KEX_DH_GEX_INIT ? $this->init($payload) : null;
    }

    /** @return string[] */
    private function request(string $payload): array
    {
        $r = new Reader($payload);
        $r->byte();
        $min = $r->uint32();
        $n = $r->uint32();
        $max = $r->uint32();

        // Range-check the RAW client values (sshd checks kex->min/nbits/max before clamping); an
        // out-of-range request is SSH_ERR_DH_GEX_OUT_OF_RANGE ⇒ disconnect.
        if ($max < $min || $n < $min || $max < $n || $max < self::DH_GRP_MIN) {
            throw new \RuntimeException('ssh: dh gex out of range');
        }

        $bits = DhGroups::choose(
            max(self::DH_GRP_MIN, $min),
            $n,
            min(self::DH_GRP_MAX, $max)
        );
        $this->reqMin = $min;
        $this->reqN = $n;
        $this->reqMax = $max;
        $this->chosenP = DhGroups::modulus($bits);
        $this->grouped = true;

        $reply = (new Buf())
            ->byte(self::MSG_KEX_DH_GEX_GROUP)
            ->mpint($this->chosenP)
            ->mpint(DhGroups::G)
            ->get();

        return [$reply];
    }

    /** @return string[] */
    private function init(string $payload): array
    {
        $p = $this->chosenP;

        $r = new Reader($payload);
        $r->byte();
        $e = $r->mpint();
        $this->validatePeerValue($e, $p);

        [$ours, $f] = $this->dhKeypair($p);
        $k = $this->dhDerive($p, $e, $ours);
        $kMpint = Buf::mpintOf($k);

        // RFC 4419 §3 / kexgex_hash: the RAW client min/n/max are hashed (the always-present REQUEST
        // path, so all three uint32 are included), then p, g, e, f, K.
        $hashInput = $this->hashPrefix()
            . (new Buf())->uint32($this->reqMin)->uint32($this->reqN)->uint32($this->reqMax)->get()
            . Buf::mpintOf($p)
            . Buf::mpintOf(DhGroups::G)
            . Buf::mpintOf($e)
            . Buf::mpintOf($f)
            . $kMpint;
        $sig = $this->finish($hashInput, $kMpint);

        $reply = (new Buf())
            ->byte(self::MSG_KEX_DH_GEX_REPLY)
            ->string($this->hostKey->publicBlob())
            ->mpint($f)
            ->string($sig)
            ->get();

        return [$reply];
    }
}
