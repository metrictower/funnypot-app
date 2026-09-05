<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Sip;

/**
 * RTP packet builder and UDP media transmitter (RFC 3550 & RFC 3551).
 * Strictly locks destination IP to the signaling peer IP (Anti-Reflection Invariant B1).
 *
 * Not final: the run-loop fault-isolation tests inject a subclass that throws from a transport method
 * to prove a media fault degrades (logged + session evicted) instead of killing the listener.
 */
class RtpStreamer
{
    /** @var resource|null UDP socket for sending RTP media (null until a return-routable dialog opens) */
    private $udpSocket = null;

    /** The one cataloged/published fixed media port. Never an ephemeral fallback (Docker cannot NAT it). */
    private int $preferredPort;

    /** @var array<string,bool> active return-routable dialog ids sharing the one media socket */
    private array $activeDialogs = [];

    public function __construct(int $preferredPort = 0)
    {
        $this->preferredPort = $preferredPort;
        // Construction does NOT bind: the media socket opens only on a return-routable dialog, so an
        // idle honeypot never holds an unused UDP port and a spoofed INVITE never opens one.
    }

    public function __destruct()
    {
        if ($this->udpSocket && is_resource($this->udpSocket)) {
            @fclose($this->udpSocket);
        }
    }

    /**
     * Open the media socket for a return-routable dialog (called after the ACK To-tag check). The first
     * active dialog binds the ONE fixed port; further dialogs share it. A fixed-port bind failure never
     * falls back to an ephemeral port — an unpublished port could not receive caller media anyway, so
     * the call simply streams no media rather than opening a socket Docker cannot reach.
     */
    public function activateDialog(string $dialogId): bool
    {
        $this->activeDialogs[$dialogId] = true;
        if ($this->udpSocket === null && $this->preferredPort > 0) {
            $sock = @stream_socket_server("udp://0.0.0.0:{$this->preferredPort}", $errno, $errstr, STREAM_SERVER_BIND);
            if ($sock) {
                stream_set_blocking($sock, false);
                $this->udpSocket = $sock;
            }
        }

        return $this->udpSocket !== null && is_resource($this->udpSocket);
    }

    /** Close the media socket once the last bounded dialog ends. */
    public function deactivateDialog(string $dialogId): void
    {
        unset($this->activeDialogs[$dialogId]);
        if ($this->activeDialogs === [] && $this->udpSocket !== null && is_resource($this->udpSocket)) {
            @fclose($this->udpSocket);
            $this->udpSocket = null;
        }
    }

    /**
     * Builds a 12-byte RFC 3550 RTP header for G.711u (PCMU, Payload Type 0).
     */
    public static function buildHeader(int $seq, int $timestamp, int $ssrc, bool $marker = false): string
    {
        $byte0 = 0x80; // V=2, P=0, X=0, CC=0
        $byte1 = ($marker ? 0x80 : 0x00) | 0x00; // Marker bit | PT=0 (PCMU)

        return pack(
            'CCnNN',
            $byte0,
            $byte1,
            $seq & 0xffff,
            $timestamp & 0xffffffff,
            $ssrc & 0xffffffff
        );
    }

    /**
     * Sends a 160-byte G.711u audio slice as an RTP packet to the session destination.
     * Enforces that the media destination IP strictly equals the signaling source IP.
     */
    public function sendPacket(SipSession $s, string $audioPayload): bool
    {
        // Anti-Reflection Check (B1): Media destination MUST match the signaling source IP
        if ($s->remoteRtpIp === '' || $s->remoteRtpIp !== $s->peerIp || $s->remoteRtpPort <= 0) {
            return false;
        }

        if (!$this->udpSocket || !is_resource($this->udpSocket)) {
            // A validated ACK opens the dialog; a send before that binds the one fixed port for this
            // session's dialog. Never an ephemeral fallback: no fixed port ⇒ no media socket.
            $this->activateDialog($s->callId);
            if (!$this->udpSocket || !is_resource($this->udpSocket)) {
                return false;
            }
        }

        // Marker bit on the very first packet of the call (RFC 3551 §4.5.1)
        $marker = ($s->rtpPacketsSent === 0);
        $header = self::buildHeader($s->rtpSeq, $s->rtpTimestamp, $s->rtpSsrc, $marker);

        // Standard 160-byte payload padding if short
        if (strlen($audioPayload) < 160) {
            $audioPayload = str_pad($audioPayload, 160, chr(0xff));
        } elseif (strlen($audioPayload) > 160) {
            $audioPayload = substr($audioPayload, 0, 160);
        }

        $packet = $header . $audioPayload;
        $dest = "{$s->remoteRtpIp}:{$s->remoteRtpPort}";

        $sent = @stream_socket_sendto($this->udpSocket, $packet, 0, $dest);
        if ($sent > 0) {
            $s->rtpSeq = ($s->rtpSeq + 1) & 0xffff;
            $s->rtpTimestamp = ($s->rtpTimestamp + 160) & 0xffffffff;
            $s->rtpPacketsSent++;

            return true;
        }

        return false;
    }

    /**
     * The advertised media port for SDP. It is the configured fixed port and does NOT imply a live
     * socket (the socket opens only on a return-routable dialog); the SDP answer must carry the fixed
     * port so a later ACK-bound socket lines up with what the caller was told.
     */
    public function getLocalPort(): int
    {
        return $this->preferredPort > 0 ? $this->preferredPort : 10000;
    }

    /**
     * @return resource|null
     */
    public function getSocket()
    {
        return $this->udpSocket;
    }

    /**
     * Reads an incoming RTP packet sent by the caller.
     * @return array{peerIp: string, peerPort: int, payload: string}|null
     */
    public function receivePacket(): ?array
    {
        if (!$this->udpSocket || !is_resource($this->udpSocket)) {
            return null;
        }

        $data = @stream_socket_recvfrom($this->udpSocket, 2048, 0, $peerAddr);
        if ($data === false || strlen($data) <= 12 || !$peerAddr) {
            return null;
        }

        $lastColon = strrpos($peerAddr, ':');
        if ($lastColon !== false) {
            $peerIp = substr($peerAddr, 0, $lastColon);
            $peerPort = (int) substr($peerAddr, $lastColon + 1);
        } else {
            $peerIp = $peerAddr;
            $peerPort = 0;
        }

        // RTP header is at least 12 bytes. Byte 1 low 7 bits = payload type; bytes 4-7 = timestamp.
        // Both are needed to spot and dedup out-of-band DTMF (telephone-event) packets.
        $pt = ord($data[1]) & 0x7f;
        $tsParts = unpack('N', substr($data, 4, 4));
        $timestamp = $tsParts ? $tsParts[1] : 0;
        $payload = substr($data, 12);

        return [
            'peerIp' => $peerIp,
            'peerPort' => $peerPort,
            'payload' => $payload,
            'pt' => $pt,
            'timestamp' => $timestamp,
        ];
    }
}
