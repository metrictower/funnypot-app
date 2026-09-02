<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh\Kex;

use Funnypot\Protocol\Ssh\Buf;
use Funnypot\Protocol\Ssh\Reader;

/**
 * Elliptic-curve Diffie-Hellman key exchange: curve25519-sha256(+@libssh.org) via libsodium
 * (RFC 8731) and ecdh-sha2-nistp256/384/521 via ext-openssl (RFC 5656). One inbound message is
 * expected — 30 (KEX_ECDH_INIT, `string Q_C`) — answered with 31 (KEX_ECDH_REPLY:
 * `string K_S, string Q_S, string sig`); anything else, or a second 30, returns null (⇒ the caller
 * answers SSH_MSG_UNIMPLEMENTED). The peer point is validated before any use: 32 bytes for X25519,
 * `04 ‖ X ‖ Y` of the exact field length for the NIST curves — for those the DER-SPKI import is
 * itself the on-curve check (openssl_pkey_get_public() returns false for an off-curve point).
 *
 * openssl_pkey_get_details()['ec']['x'|'y'] are minimal big-endian, so Q_S is built by left-padding
 * X and Y to the field length (32/48/66) — an unpadded coordinate yields a malformed point.
 */
final class Ecdh extends AbstractKex
{
    private const MSG_KEX_ECDH_INIT = 30;
    private const MSG_KEX_ECDH_REPLY = 31;

    // 1.2.840.10045.2.1 id-ecPublicKey, DER-encoded.
    private const OID_EC_PUBLIC_KEY = "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";

    public function handle(int $msg, string $payload): ?array
    {
        if ($this->result !== null || $msg !== self::MSG_KEX_ECDH_INIT) {
            return null;
        }
        $r = new Reader($payload);
        $r->byte();
        $qC = $r->string();

        if ($this->name === 'curve25519-sha256' || $this->name === 'curve25519-sha256@libssh.org') {
            return [$this->curve25519($qC)];
        }

        return [$this->nist($qC)];
    }

    private function curve25519(string $qC): string
    {
        if (strlen($qC) !== 32) {
            throw new \RuntimeException('ssh: bad client ephemeral key length');
        }
        $priv = random_bytes(32);
        $qS = sodium_crypto_scalarmult_base($priv);
        $shared = sodium_crypto_scalarmult($priv, $qC); // throws on all-zero output
        $kMpint = Buf::mpintOf($shared);

        $hashInput = $this->hashPrefix() . Buf::stringOf($qC) . Buf::stringOf($qS) . $kMpint;
        $sig = $this->finish($hashInput, $kMpint);

        return (new Buf())
            ->byte(self::MSG_KEX_ECDH_REPLY)
            ->string($this->hostKey->publicBlob())
            ->string($qS)
            ->string($sig)
            ->get();
    }

    private function nist(string $qC): string
    {
        [$curve, $flen, $curveOid] = $this->curveParams();
        if (strlen($qC) !== 2 * $flen + 1 || $qC[0] !== "\x04") {
            throw new \RuntimeException('ssh: invalid ecdh point');
        }
        $peer = openssl_pkey_get_public($this->spkiPem($qC, $curveOid));
        if ($peer === false) {
            // Off-curve or otherwise malformed: the import is the validation.
            while (openssl_error_string() !== false) {
                // drain the error queue
            }
            throw new \RuntimeException('ssh: invalid ecdh point');
        }

        $ours = openssl_pkey_new(['curve_name' => $curve, 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        if ($ours === false) {
            throw new \RuntimeException('ssh: ecdh keygen failed');
        }
        $details = openssl_pkey_get_details($ours);
        $qS = "\x04"
            . str_pad($details['ec']['x'], $flen, "\x00", STR_PAD_LEFT)
            . str_pad($details['ec']['y'], $flen, "\x00", STR_PAD_LEFT);

        $k = openssl_pkey_derive($peer, $ours);
        if ($k === false) {
            throw new \RuntimeException('ssh: ecdh derive failed');
        }
        $kMpint = Buf::mpintOf($k); // RFC 5656 §4: K is the x-coordinate as an mpint

        $hashInput = $this->hashPrefix() . Buf::stringOf($qC) . Buf::stringOf($qS) . $kMpint;
        $sig = $this->finish($hashInput, $kMpint);

        return (new Buf())
            ->byte(self::MSG_KEX_ECDH_REPLY)
            ->string($this->hostKey->publicBlob())
            ->string($qS)
            ->string($sig)
            ->get();
    }

    /** @return array{0:string,1:int,2:string} [openssl curve name, field length, DER curve OID] */
    private function curveParams(): array
    {
        return match ($this->name) {
            'ecdh-sha2-nistp256' => ['prime256v1', 32, "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"],
            'ecdh-sha2-nistp384' => ['secp384r1', 48, "\x06\x05\x2b\x81\x04\x00\x22"],
            'ecdh-sha2-nistp521' => ['secp521r1', 66, "\x06\x05\x2b\x81\x04\x00\x23"],
            default => throw new \RuntimeException("ssh: unsupported ecdh curve {$this->name}"),
        };
    }

    /** Wrap an uncompressed EC point as a PEM SubjectPublicKeyInfo for openssl_pkey_get_public(). */
    private function spkiPem(string $point, string $curveOid): string
    {
        $spki = self::derSeq(
            self::derSeq(self::OID_EC_PUBLIC_KEY . $curveOid)
            . self::derBitString($point)
        );

        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($spki), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    private static function derLen(int $n): string
    {
        if ($n < 0x80) {
            return chr($n);
        }
        $b = '';
        while ($n > 0) {
            $b = chr($n & 0xff) . $b;
            $n >>= 8;
        }

        return chr(0x80 | strlen($b)) . $b;
    }

    private static function derSeq(string $content): string
    {
        return "\x30" . self::derLen(strlen($content)) . $content;
    }

    private static function derBitString(string $content): string
    {
        $content = "\x00" . $content; // zero unused bits

        return "\x03" . self::derLen(strlen($content)) . $content;
    }
}
