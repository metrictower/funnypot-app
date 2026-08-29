<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Sip;

/**
 * Tracks the state of an active SIP dialog and its associated RTP media stream.
 */
final class SipSession
{
    public const STATE_IDLE = 'idle';
    public const STATE_TRYING = 'trying';
    public const STATE_RINGING = 'ringing';
    public const STATE_CONNECTED = 'connected';
    public const STATE_STREAMING = 'streaming';
    public const STATE_ENDED = 'ended';

    public string $state = self::STATE_IDLE;

    public string $callId = '';
    public string $fromTag = '';
    public string $toTag = '';
    public int $cseqNumber = 1;
    public string $cseqMethod = 'INVITE';

    public string $peerIp = '';
    public int $peerPort = 5060;
    public string $transport = 'udp'; // 'udp' | 'tcp'

    /** @var resource|null TCP stream handle (if transport is TCP) */
    public $tcpSocket = null;
    public string $tcpInbuf = '';

    public string $dialedNumber = 'unknown';
    public string $persona = 'lenny';

    // RTP Media destination and streaming parameters
    public string $remoteRtpIp = '';
    public int $remoteRtpPort = 0;
    public int $rtpSeq = 0;
    public int $rtpTimestamp = 0;
    public int $rtpSsrc = 0;
    public int $rtpPacketsSent = 0;

    public float $startTime = 0.0;
    public float $lastRtpSendTime = 0.0;
    // Last time the CALLER sent us anything (RTP or signaling). Drives hangup/idle detection —
    // distinct from lastRtpSendTime, which tracks our own outbound stream clock.
    public float $lastInboundTime = 0.0;

    // Soundboard pacing state
    public int $personaClipIndex = 0;
    public int $personaClipOffset = 0;
    public int $personaPauseRemaining = 0;

    // Call recording buffers: our outbound persona stream, and the caller's inbound stream
    // (the intel). Written as the two channels of a stereo recording.
    public string $recordedUlaw = '';
    public string $recordedInbound = '';
    public string $recordingUrl = '';

    public function __construct(string $callId, string $peerIp, int $peerPort, string $transport = 'udp')
    {
        $this->callId = $callId;
        $this->peerIp = $peerIp;
        $this->peerPort = $peerPort;
        $this->transport = $transport;

        // Strictly pin the RTP destination IP to the incoming signaling source IP (Anti-Reflection Invariant B1)
        $this->remoteRtpIp = $peerIp;

        $this->toTag = bin2hex(random_bytes(4));
        $this->rtpSeq = random_int(1000, 50000);
        $this->rtpTimestamp = random_int(10000, 500000);
        $this->rtpSsrc = random_int(100000, 9999999);
        $this->startTime = microtime(true);
    }

    public function isStreaming(): bool
    {
        return ($this->state === self::STATE_CONNECTED || $this->state === self::STATE_STREAMING) && $this->remoteRtpPort > 0;
    }

    public function getDuration(): float
    {
        return max(0.0, microtime(true) - $this->startTime);
    }
}
