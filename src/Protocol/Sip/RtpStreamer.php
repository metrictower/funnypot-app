<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Sip;

/**
 * RTP packet builder and UDP media transmitter (RFC 3550 & RFC 3551).
 * Strictly locks destination IP to the signaling peer IP (Anti-Reflection Invariant B1).
 */
final class RtpStreamer
{
    /** @var resource|null UDP socket for sending RTP media */
    private $udpSocket = null;

    public function __construct()
    {
        $this->initSocket();
    }

    public function __destruct()
    {
        if ($this->udpSocket && is_resource($this->udpSocket)) {
            @fclose($this->udpSocket);
        }
    }

    private function initSocket(): void
    {
        $sock = @stream_socket_server('udp://0.0.0.0:0', $errno, $errstr, STREAM_SERVER_BIND);
        if ($sock) {
            stream_set_blocking($sock, false);
            $this->udpSocket = $sock;
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
            $this->initSocket();
            if (!$this->udpSocket) {
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
     * Local UDP port bound by this RTP streamer instance.
     */
    public function getLocalPort(): int
    {
        if ($this->udpSocket && is_resource($this->udpSocket)) {
            $name = stream_socket_get_name($this->udpSocket, false);
            if ($name && preg_match('/:(\d+)$/', $name, $m)) {
                return (int) $m[1];
            }
        }

        return 10000;
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

        // RTP header is at least 12 bytes
        $payload = substr($data, 12);

        return [
            'peerIp' => $peerIp,
            'peerPort' => $peerPort,
            'payload' => $payload,
        ];
    }
}
