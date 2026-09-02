<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh;

use Funnypot\Protocol\Ssh\Cipher\PacketCipher;
use Funnypot\Protocol\Ssh\Cipher\PlainCipher;

/**
 * The SSH binary packet protocol (RFC 4253 §6) for one connection: framing, padding, and — once
 * keys are installed — sealing each packet through a {@see PacketCipher}. Send and receive run
 * independently, each with its own cipher and a monotonic 32-bit sequence number that spans the
 * plaintext KEX packets and continues into the encrypted stream — unless strict kex is negotiated,
 * in which case each direction restarts its counter at 0 after its NEWKEYS (PROTOCOL §1.9(b)),
 * driven by the $resetSeq flag on {@see enableSend()} / {@see enableRecv()}. The reset applies to
 * every NEWKEYS under strict (§1.9(b) — it persists for the duration of the connection), not just
 * the first. Before NEWKEYS both directions use {@see PlainCipher} (no encryption, no MAC), so one
 * code path serves both phases.
 *
 * The padding rule ({@see padLen()}) is aadlen-aware: E&M includes the 4-byte length in the
 * alignment, while ETM/GCM/chacha exclude it (OpenSSH packet.c `ssh_packet_send2_wrapped`). Using
 * the E&M rule for an AEAD/ETM cipher would produce a packet_length the client rejects on the first
 * encrypted packet, so the rule is a function of the installed cipher's blockSize()/aadLen().
 *
 * `frame()` builds an outbound packet from a payload; `next()` pulls one inbound payload from the
 * running buffer, returning null when more bytes are needed.
 */
final class Transport
{
    private const MAX_PACKET = 35000; // guard against absurd length fields

    private int $outSeq = 0;
    private int $inSeq = 0;
    private int $lastInSeq = 0; // sequence number of the packet most recently returned by next()

    private PacketCipher $send;
    private PacketCipher $recv;

    // Cached packet length once the head of an inbound packet has been read; held until the whole
    // packet arrives (and, for E&M, so the first-block decrypt is not repeated).
    private ?int $pktLen = null;

    public function __construct()
    {
        $this->send = new PlainCipher();
        $this->recv = new PlainCipher();
    }

    /**
     * RFC 4253 §6 padding. The bytes covered by the block alignment exclude the aadLen head
     * (0 for E&M/plain, 4 for ETM/AEAD), matching OpenSSH packet.c; at least 4 pad bytes.
     */
    public static function padLen(int $payloadLen, int $block, int $aadLen): int
    {
        $aligned = (4 - $aadLen) + 1 + $payloadLen; // E&M: 4+1+payload ; ETM/AEAD: 1+payload
        $pad = $block - ($aligned % $block);

        return $pad < 4 ? $pad + $block : $pad;
    }

    /** Build the wire bytes for one outbound packet carrying $payload. */
    public function frame(string $payload): string
    {
        $pad = self::padLen(strlen($payload), $this->send->blockSize(), $this->send->aadLen());
        $packet = pack('N', 1 + strlen($payload) + $pad) . chr($pad) . $payload . random_bytes($pad);
        $wire = $this->send->seal($this->outSeq, $packet);
        $this->outSeq = ($this->outSeq + 1) & 0xffffffff;

        return $wire;
    }

    /**
     * Pull one inbound packet payload from $buffer (consuming its bytes), or return null if the
     * buffer does not yet hold a complete packet. Throws on a malformed packet or bad MAC/tag.
     */
    public function next(string &$buffer): ?string
    {
        $head = $this->recv->headLen();
        if ($this->pktLen === null) {
            if (strlen($buffer) < $head) {
                return null;
            }
            $pktLen = $this->recv->peekLength($this->inSeq, substr($buffer, 0, $head));
            $aligned = (4 - $this->recv->aadLen()) + $pktLen;
            if ($pktLen < 5 || $pktLen > self::MAX_PACKET || $aligned % $this->recv->blockSize() !== 0) {
                throw new \RuntimeException('ssh: bad packet length');
            }
            $this->pktLen = $pktLen;
        }
        $total = 4 + $this->pktLen + $this->recv->tagLen();
        if (strlen($buffer) < $total) {
            return null;
        }
        $packet = $this->recv->open($this->inSeq, substr($buffer, 0, $total));
        $packetLen = $this->pktLen;
        $buffer = substr($buffer, $total);
        $this->pktLen = null;
        $this->lastInSeq = $this->inSeq;
        $this->inSeq = ($this->inSeq + 1) & 0xffffffff;

        return $this->payloadOf($packet, $packetLen);
    }

    private function payloadOf(string $packet, int $packetLen): string
    {
        $pad = ord($packet[4]);
        $payloadLen = $packetLen - 1 - $pad;
        if ($pad < 4 || $payloadLen < 0) {
            throw new \RuntimeException('ssh: bad padding');
        }

        return substr($packet, 5, $payloadLen);
    }

    /**
     * Install the server→client cipher; subsequent frames are sealed through it. Under strict kex
     * ($resetSeq true) the outbound sequence number restarts at 0 — the packet just framed was our
     * NEWKEYS, so the next packet (EXT_INFO) is numbered 0 (OpenSSH packet.c:1224-1227).
     */
    public function enableSend(PacketCipher $cipher, bool $resetSeq = false): void
    {
        $this->send = $cipher;
        if ($resetSeq) {
            $this->outSeq = 0;
        }
    }

    /**
     * Install the client→server cipher; subsequent packets are opened through it. Under strict kex
     * ($resetSeq true) the inbound sequence number restarts at 0 — the packet just consumed was the
     * client's NEWKEYS, so its next packet opens at 0 (OpenSSH packet.c:1693-1696).
     */
    public function enableRecv(PacketCipher $cipher, bool $resetSeq = false): void
    {
        $this->recv = $cipher;
        if ($resetSeq) {
            $this->inSeq = 0;
        }
    }

    /**
     * Sequence number of the packet most recently returned by {@see next()} — used for
     * SSH_MSG_UNIMPLEMENTED and the strict-kex "KEXINIT must be the first packet" rule.
     */
    public function lastInSeq(): int
    {
        return $this->lastInSeq;
    }
}
